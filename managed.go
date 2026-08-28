package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"
)

const managedMessageLimit = 4096
const instanceHeader = "X-GoHTTPX-Instance"

type managedBootstrap struct {
	RuntimeProtocolVersion int    `json:"runtime_protocol_version"`
	InstanceID             string `json:"instance_id"`
	Token                  string `json:"token"`
	OwnerPID               int    `json:"owner_pid"`
	SDKVersion             string `json:"sdk_version"`
}

func readBootstrap(reader *bufio.Reader) (managedBootstrap, error) {
	var input managedBootstrap
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) >= managedMessageLimit || decodeStrictJSON(line, &input) != nil {
		return input, errors.New("managed bootstrap 无效")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	_, _ = decoder.Token()
	seen := make(map[string]bool)
	for decoder.More() {
		key, _ := decoder.Token()
		name, ok := key.(string)
		if !ok || seen[name] {
			return input, errors.New("managed bootstrap 包含重复字段")
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return input, errors.New("managed bootstrap 无效")
		}
	}
	identity, identityErr := hex.DecodeString(input.InstanceID)
	token, tokenErr := hex.DecodeString(input.Token)
	if input.RuntimeProtocolVersion != 1 || input.SDKVersion != serverVersion || input.OwnerPID <= 0 || identityErr != nil || len(identity) != 16 || tokenErr != nil || len(token) != 32 {
		return input, errors.New("managed bootstrap 版本或身份无效")
	}
	return input, nil
}

func runManaged(options cliOptions, input io.Reader, output io.Writer) error {
	reader := bufio.NewReaderSize(input, managedMessageLimit)
	type bootstrapResult struct {
		value managedBootstrap
		err   error
	}
	bootstrap := make(chan bootstrapResult, 1)
	go func() {
		value, err := readBootstrap(reader)
		bootstrap <- bootstrapResult{value, err}
	}()
	var config managedBootstrap
	select {
	case result := <-bootstrap:
		if result.err != nil {
			// 固定错误码不回显 token，允许 SDK 将版本/协议错误识别为不可重试配置错误。
			_ = json.NewEncoder(output).Encode(map[string]any{"runtime_protocol_version": 1, "error": "BOOTSTRAP_REJECTED"})
			return result.err
		}
		config = result.value
	case <-time.After(10 * time.Second):
		return errors.New("managed bootstrap 超时")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("managed listener 创建失败")
	}
	defer listener.Close()
	registry := newServer(config.Token, options.maxBodyMiB<<20, options.idleTTL)
	registry.instanceID = config.InstanceID
	defer registry.Close()
	server := &http.Server{Handler: registry.routes(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	ready := struct {
		RuntimeProtocolVersion int    `json:"runtime_protocol_version"`
		InstanceID             string `json:"instance_id"`
		ServerVersion          string `json:"server_version"`
		ProtocolVersion        int    `json:"protocol_version"`
		PID                    int    `json:"pid"`
		Host                   string `json:"host"`
		Port                   int    `json:"port"`
	}{1, config.InstanceID, serverVersion, protocolVersion, os.Getpid(), "127.0.0.1", listener.Addr().(*net.TCPAddr).Port}
	if json.NewEncoder(output).Encode(ready) != nil {
		_ = server.Close()
		return errors.New("managed ready 写入失败")
	}
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		// 私有管道消失、消息损坏均结束实例，不允许脱离所属 Python 继续运行。
		line, readErr := reader.ReadSlice('\n')
		if readErr != nil || len(line) >= managedMessageLimit {
			return
		}
		// 私有管道只支持 shutdown；任何输入均视为父进程结束本实例的意图。
	}()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	select {
	case <-stop:
	case <-interrupt:
	case err := <-served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.New("managed HTTP 服务退出")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if server.Shutdown(ctx) != nil {
		_ = server.Close()
	}
	<-served
	return nil
}
