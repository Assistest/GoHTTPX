package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/dicttls"
)

const maxTLSSpecBytes = 64 << 10

// 保存声明而不是 uTLS 对象；ApplyPreset 会修改扩展，不能跨连接共享。
type tlsSpec struct {
	CipherSuites       []string          `json:"cipher_suites"`
	CompressionMethods []string          `json:"compression_methods"`
	Extensions         []json.RawMessage `json:"extensions"`
	MinVersion         uint16            `json:"min_vers,omitempty"`
	MaxVersion         uint16            `json:"max_vers,omitempty"`
	ShuffleExtensions  bool              `json:"shuffle_extensions,omitempty"`
}

func (s *tlsSpec) UnmarshalJSON(data []byte) error {
	if len(data) > maxTLSSpecBytes {
		return errors.New("tls_spec exceeds 65536 bytes")
	}
	if err := checkTLSJSON(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for name := range fields {
		if !slices.Contains([]string{"cipher_suites", "compression_methods", "extensions", "min_vers", "max_vers", "shuffle_extensions"}, name) {
			return fmt.Errorf("unknown tls_spec field %q", name)
		}
	}
	type wire tlsSpec
	if err := decodeStrictJSON(data, (*wire)(s)); err != nil {
		return err
	}
	_, err := s.clientHelloSpec()
	return err
}

func checkTLSJSON(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("tls_spec nesting exceeds 8")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("tls_spec cannot contain null")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("tls_spec contains duplicate JSON keys")
			}
			seen[name] = true
		}
		if err := checkTLSJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func tlsObject(data []byte, required ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, errors.New("TLS extension must be an object")
	}
	if len(fields) != len(required) {
		return nil, errors.New("TLS extension contains missing or unsupported fields")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return nil, fmt.Errorf("TLS extension requires %s", name)
		}
	}
	return fields, nil
}

func tlsNames(data json.RawMessage, limit int) ([]string, error) {
	var names []string
	if err := json.Unmarshal(data, &names); err != nil || len(names) == 0 || len(names) > limit {
		return nil, errors.New("TLS field must be a bounded nonempty string array")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || len(name) > 128 || seen[name] {
			return nil, errors.New("TLS field contains empty, duplicate or oversized names")
		}
		seen[name] = true
	}
	return names, nil
}

func tlsIDs(names []string, dictionary map[string]uint16) ([]uint16, error) {
	ids := make([]uint16, len(names))
	seen := map[uint16]bool{}
	for i, name := range names {
		id, ok := dictionary[name]
		switch {
		case name == "GREASE":
			id, ok = utls.GREASE_PLACEHOLDER, true
		case name == "X25519MLKEM768" && dictionary["x25519"] != 0:
			id, ok = uint16(utls.X25519MLKEM768), true
		case strings.HasPrefix(name, "0x"):
			value, err := strconv.ParseUint(name[2:], 16, 16)
			id, ok = uint16(value), err == nil
		}
		if id&0x0f0f == 0x0a0a && id>>8 == id&255 {
			id = utls.GREASE_PLACEHOLDER
		}
		if !ok || seen[id] {
			return nil, fmt.Errorf("unknown or duplicate TLS identifier %q", name)
		}
		seen[id] = true
		ids[i] = id
	}
	return ids, nil
}

func (s *tlsSpec) clientHelloSpec() (*utls.ClientHelloSpec, error) {
	if len(s.CipherSuites) == 0 || len(s.CipherSuites) > 128 || len(s.Extensions) == 0 || len(s.Extensions) > 64 {
		return nil, errors.New("tls_spec requires 1..128 cipher suites and 1..64 extensions")
	}
	if !slices.Equal(s.CompressionMethods, []string{"NULL"}) {
		return nil, errors.New("compression_methods must be [NULL]")
	}
	ciphers, err := tlsIDs(s.CipherSuites, dicttls.DictCipherSuiteNameIndexed)
	if err != nil {
		return nil, err
	}
	spec := &utls.ClientHelloSpec{CipherSuites: ciphers, CompressionMethods: []byte{0}}
	seen := map[string]int{}
	var versions []uint16
	var groups []utls.CurveID
	var shares []utls.KeyShare
	var alpn, alps []string
	for _, data := range s.Extensions {
		name, extension, err := parseTLSExtension(data)
		if err != nil {
			return nil, err
		}
		seen[name]++
		if seen[name] > 1 && name != "GREASE" || seen[name] > 2 {
			return nil, errors.New("duplicate TLS extension")
		}
		switch ext := extension.(type) {
		case *utls.SupportedVersionsExtension:
			versions = ext.Versions
		case *utls.SupportedCurvesExtension:
			groups = ext.Curves
		case *utls.KeyShareExtension:
			shares = ext.KeyShares
		case *utls.ALPNExtension:
			alpn = ext.AlpnProtocols
		case *utls.ApplicationSettingsExtension:
			alps = ext.SupportedProtocols
		case *utls.ApplicationSettingsExtensionNew:
			alps = ext.SupportedProtocols
		}
		spec.Extensions = append(spec.Extensions, extension)
	}
	if len(versions) == 0 || seen["signature_algorithms"] == 0 {
		return nil, errors.New("supported_versions and signature_algorithms are required")
	}
	minVersion, maxVersion := uint16(utls.VersionTLS13), uint16(utls.VersionTLS12)
	for _, version := range versions {
		if version == utls.GREASE_PLACEHOLDER {
			continue
		}
		if version != utls.VersionTLS12 && version != utls.VersionTLS13 {
			return nil, errors.New("only TLS 1.2 and TLS 1.3 are supported")
		}
		minVersion = min(minVersion, version)
		maxVersion = max(maxVersion, version)
	}
	if minVersion > maxVersion || s.MinVersion != 0 && s.MinVersion != minVersion || s.MaxVersion != 0 && s.MaxVersion != maxVersion {
		return nil, errors.New("min_vers/max_vers conflict with supported_versions")
	}
	spec.TLSVersMin, spec.TLSVersMax = minVersion, maxVersion
	if maxVersion == utls.VersionTLS13 && len(shares) == 0 {
		return nil, errors.New("TLS 1.3 requires key_share")
	}
	if maxVersion == utls.VersionTLS13 && !slices.Contains(ciphers, uint16(utls.TLS_AES_128_GCM_SHA256)) &&
		!slices.Contains(ciphers, uint16(utls.TLS_AES_256_GCM_SHA384)) && !slices.Contains(ciphers, uint16(utls.TLS_CHACHA20_POLY1305_SHA256)) {
		return nil, errors.New("TLS 1.3 requires an implemented TLS 1.3 cipher suite")
	}
	if len(shares) == 1 && shares[0].Group == utls.GREASE_PLACEHOLDER {
		return nil, errors.New("key_share requires a real key exchange group")
	}
	for _, share := range shares {
		if !slices.Contains(groups, share.Group) {
			return nil, errors.New("key_share group must appear in supported_groups")
		}
	}
	for _, protocol := range alps {
		if !slices.Contains(alpn, protocol) {
			return nil, errors.New("application_settings protocol must appear in ALPN")
		}
	}
	if seen["application_settings"] > 0 && seen["application_settings_new"] > 0 {
		return nil, errors.New("choose one application_settings codepoint")
	}
	if s.ShuffleExtensions {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}
	return spec, nil
}

func parseTLSExtension(data []byte) (string, utls.TLSExtension, error) {
	var header struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return "", nil, err
	}
	name := header.Name
	field := map[string]string{
		"supported_groups": "named_group_list", "ec_point_formats": "ec_point_format_list",
		"signature_algorithms": "supported_signature_algorithms", "delegated_credentials": "supported_signature_algorithms",
		"supported_versions": "versions", "record_size_limit": "record_size_limit",
		"application_layer_protocol_negotiation": "protocol_name_list", "key_share": "client_shares",
		"psk_key_exchange_modes": "ke_modes", "compress_certificate": "algorithms",
		"application_settings": "supported_protocols", "application_settings_new": "supported_protocols",
	}[name]
	if name == "encrypted_client_hello" {
		extension, err := parseTLSGREASEECH(data)
		return name, extension, err
	}
	required := []string{"name"}
	if field != "" {
		required = append(required, field)
	}
	fields, err := tlsObject(data, required...)
	if err != nil {
		return name, nil, err
	}
	if name == "key_share" {
		ext, err := parseTLSKeyShares(fields[field])
		return name, ext, err
	}
	if name == "record_size_limit" {
		var limit uint16
		if err := json.Unmarshal(fields[field], &limit); err != nil || limit < 64 || limit > 16385 {
			return name, nil, errors.New("record_size_limit must be an integer between 64 and 16385")
		}
		return name, &utls.FakeRecordSizeLimitExtension{Limit: limit}, nil
	}
	var names []string
	if field != "" {
		names, err = tlsNames(fields[field], 64)
		if err != nil {
			return name, nil, err
		}
	}
	var extension utls.TLSExtension
	switch name {
	case "GREASE":
		extension = &utls.UtlsGREASEExtension{}
	case "server_name":
		extension = &utls.SNIExtension{}
	case "status_request":
		extension = &utls.StatusRequestExtension{}
	case "signed_certificate_timestamp":
		extension = &utls.SCTExtension{}
	case "extended_master_secret":
		extension = &utls.ExtendedMasterSecretExtension{}
	case "session_ticket":
		extension = &utls.SessionTicketExtension{}
	case "renegotiation_info":
		extension = &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}
	case "supported_groups", "signature_algorithms", "delegated_credentials":
		dictionary := dicttls.DictSupportedGroupsNameIndexed
		if name != "supported_groups" {
			dictionary = dicttls.DictSignatureSchemeNameIndexed
		}
		ids, err := tlsIDs(names, dictionary)
		if err != nil {
			return name, nil, err
		}
		if name == "supported_groups" {
			ext := &utls.SupportedCurvesExtension{}
			for _, id := range ids {
				ext.Curves = append(ext.Curves, utls.CurveID(id))
			}
			extension = ext
		} else if name == "signature_algorithms" {
			ext := &utls.SignatureAlgorithmsExtension{}
			for _, id := range ids {
				ext.SupportedSignatureAlgorithms = append(ext.SupportedSignatureAlgorithms, utls.SignatureScheme(id))
			}
			extension = ext
		} else {
			ext := &utls.DelegatedCredentialsExtension{}
			for _, id := range ids {
				ext.SupportedSignatureAlgorithms = append(ext.SupportedSignatureAlgorithms, utls.SignatureScheme(id))
			}
			extension = ext
		}
		return name, extension, nil
	case "ec_point_formats":
		if !slices.Equal(names, []string{"uncompressed"}) {
			return name, nil, errors.New("only uncompressed EC points are supported")
		}
		extension = &utls.SupportedPointsExtension{}
	case "supported_versions":
		extension = &utls.SupportedVersionsExtension{}
	case "psk_key_exchange_modes":
		if !slices.Equal(names, []string{"psk_dhe_ke"}) {
			return name, nil, errors.New("only psk_dhe_ke is supported")
		}
		extension = &utls.PSKKeyExchangeModesExtension{}
	case "compress_certificate":
		for _, algorithm := range names {
			if algorithm != "brotli" && algorithm != "zlib" && algorithm != "zstd" {
				return name, nil, errors.New("unsupported certificate compression")
			}
		}
		extension = &utls.UtlsCompressCertExtension{}
	case "application_layer_protocol_negotiation", "application_settings", "application_settings_new":
		for _, protocol := range names {
			if protocol != "h2" && protocol != "http/1.1" {
				return name, nil, errors.New("only h2 and http/1.1 ALPN are supported")
			}
		}
		switch name {
		case "application_layer_protocol_negotiation":
			extension = &utls.ALPNExtension{}
		case "application_settings":
			extension = &utls.ApplicationSettingsExtension{}
		default:
			extension = &utls.ApplicationSettingsExtensionNew{}
		}
	default:
		return name, nil, fmt.Errorf("unsupported TLS extension %q", name)
	}
	// 无参数扩展已经构造完毕；其余沿用 uTLS 原生 JSON 字段和解析。
	if field != "" {
		err = json.Unmarshal(data, extension)
	}
	return name, extension, err
}

func parseTLSGREASEECH(data []byte) (*utls.GREASEEncryptedClientHelloExtension, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, errors.New("TLS extension must be an object")
	}
	for name := range fields {
		if !slices.Contains([]string{"name", "candidate_cipher_suites", "candidate_config_ids", "candidate_payload_lens"}, name) {
			return nil, errors.New("TLS extension contains unsupported ECH fields")
		}
	}
	if len(fields) == 1 {
		return utls.BoringGREASEECH(), nil
	}
	ext := &utls.GREASEEncryptedClientHelloExtension{}
	if raw, ok := fields["candidate_cipher_suites"]; ok {
		var candidates []json.RawMessage
		if json.Unmarshal(raw, &candidates) != nil || len(candidates) == 0 || len(candidates) > 8 {
			return nil, errors.New("candidate_cipher_suites requires 1..8 entries")
		}
		seen := map[[2]uint16]bool{}
		for _, candidate := range candidates {
			parts, err := tlsObject(candidate, "kdf_id", "aead_id")
			if err != nil {
				return nil, err
			}
			var kdfID, aeadID uint16
			if json.Unmarshal(parts["kdf_id"], &kdfID) != nil || json.Unmarshal(parts["aead_id"], &aeadID) != nil ||
				!slices.Contains([]uint16{1, 2, 3}, kdfID) || !slices.Contains([]uint16{1, 2, 3}, aeadID) || seen[[2]uint16{kdfID, aeadID}] {
				return nil, errors.New("ECH cipher suite contains unsupported or duplicate kdf_id/aead_id")
			}
			seen[[2]uint16{kdfID, aeadID}] = true
			ext.CandidateCipherSuites = append(ext.CandidateCipherSuites, utls.HPKESymmetricCipherSuite{KdfId: kdfID, AeadId: aeadID})
		}
	}
	if raw, ok := fields["candidate_config_ids"]; ok {
		var ids []uint16
		if json.Unmarshal(raw, &ids) != nil || len(ids) == 0 || len(ids) > 32 {
			return nil, errors.New("candidate_config_ids requires 1..32 byte values")
		}
		seen := map[uint8]bool{}
		for _, value := range ids {
			id := uint8(value)
			if value > 255 || seen[id] {
				return nil, errors.New("candidate_config_ids contains invalid or duplicate values")
			}
			seen[id] = true
			ext.CandidateConfigIds = append(ext.CandidateConfigIds, id)
		}
	}
	if raw, ok := fields["candidate_payload_lens"]; ok {
		if json.Unmarshal(raw, &ext.CandidatePayloadLens) != nil || len(ext.CandidatePayloadLens) == 0 || len(ext.CandidatePayloadLens) > 8 {
			return nil, errors.New("candidate_payload_lens requires 1..8 entries")
		}
		seen := map[uint16]bool{}
		for _, size := range ext.CandidatePayloadLens {
			if size == 0 || size > 4096 || seen[size] {
				return nil, errors.New("candidate_payload_lens contains invalid or duplicate lengths")
			}
			seen[size] = true
		}
	}
	return ext, nil
}

func parseTLSKeyShares(data []byte) (*utls.KeyShareExtension, error) {
	var shares []json.RawMessage
	if err := json.Unmarshal(data, &shares); err != nil || len(shares) == 0 || len(shares) > 4 {
		return nil, errors.New("client_shares requires 1..4 entries")
	}
	ext := &utls.KeyShareExtension{}
	seen := map[uint16]bool{}
	for _, raw := range shares {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, err
		}
		required := []string{"group"}
		if _, ok := fields["key_exchange"]; ok {
			required = append(required, "key_exchange")
		}
		if _, err := tlsObject(raw, required...); err != nil {
			return nil, err
		}
		var group string
		if err := json.Unmarshal(fields["group"], &group); err != nil {
			return nil, err
		}
		ids, err := tlsIDs([]string{group}, dicttls.DictSupportedGroupsNameIndexed)
		if err != nil {
			return nil, err
		}
		id := ids[0]
		if seen[id] {
			return nil, errors.New("duplicate key_share group")
		}
		seen[id] = true
		var key []byte
		if id == utls.GREASE_PLACEHOLDER {
			key = []byte{0}
			if value, ok := fields["key_exchange"]; ok {
				var values []int
				if json.Unmarshal(value, &values) != nil || !slices.Equal(values, []int{0}) {
					return nil, errors.New("GREASE key_exchange must be [0]")
				}
			}
		} else {
			if _, ok := fields["key_exchange"]; ok {
				return nil, errors.New("key_exchange must be generated per connection")
			}
			switch utls.CurveID(id) {
			case utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521, utls.X25519MLKEM768:
			default:
				return nil, errors.New("unsupported key_share group")
			}
		}
		ext.KeyShares = append(ext.KeyShares, utls.KeyShare{Group: utls.CurveID(id), Data: key})
	}
	return ext, nil
}
