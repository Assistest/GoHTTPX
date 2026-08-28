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
		"signature_algorithms": "supported_signature_algorithms", "supported_versions": "versions",
		"application_layer_protocol_negotiation": "protocol_name_list", "key_share": "client_shares",
		"psk_key_exchange_modes": "ke_modes", "compress_certificate": "algorithms",
		"application_settings": "supported_protocols", "application_settings_new": "supported_protocols",
	}[name]
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
	case "encrypted_client_hello":
		extension = utls.BoringGREASEECH()
	case "supported_groups", "signature_algorithms":
		dictionary := dicttls.DictSupportedGroupsNameIndexed
		if name == "signature_algorithms" {
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
		} else {
			ext := &utls.SignatureAlgorithmsExtension{}
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
			if algorithm != "brotli" && algorithm != "zlib" {
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
