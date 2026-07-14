package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"
)

type cliOptions struct {
	host             string
	port             int
	token            string
	insecureNoAuth   bool
	allowNonLoopback bool
	maxBodyMiB       int64
	idleTTL          time.Duration
	version          bool
}

func exitError(value any) {
	fmt.Fprintln(os.Stderr, value)
	os.Exit(1)
}

func parseCLI(args []string, environmentToken string) (cliOptions, error) {
	options := cliOptions{token: environmentToken}
	flags := flag.NewFlagSet("gohttpx-server", flag.ContinueOnError)
	flags.StringVar(&options.host, "host", "127.0.0.1", "监听主机")
	flags.IntVar(&options.port, "port", 9876, "监听端口")
	flags.StringVar(&options.token, "token", environmentToken, "Bearer token")
	flags.BoolVar(&options.insecureNoAuth, "insecure-no-auth", false, "禁用鉴权（仅限开发）")
	flags.BoolVar(&options.allowNonLoopback, "allow-non-loopback", false, "允许监听非 loopback 地址")
	flags.Int64Var(&options.maxBodyMiB, "max-body-mib", 48, "最大目标请求与响应正文（MiB）")
	flags.DurationVar(&options.idleTTL, "idle-ttl", 24*time.Hour, "空闲会话生存时间")
	flags.BoolVar(&options.version, "version", false, "输出版本信息")
	return options, flags.Parse(args)
}

func main() {
	options, err := parseCLI(os.Args[1:], os.Getenv("GOHTTPX_TOKEN"))
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		exitError(err)
	}
	if options.version {
		fmt.Println(versionLine())
		return
	}

	ip := net.ParseIP(options.host)
	if !options.allowNonLoopback && options.host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		exitError("拒绝监听非 loopback 地址；如确有需要，请显式传入 --allow-non-loopback")
	}
	if options.port < 1 || options.port > 65535 {
		exitError("端口必须在 1 到 65535 之间")
	}
	if options.maxBodyMiB < 1 || options.maxBodyMiB > (1<<63-1)/(1<<20) {
		exitError("--max-body-mib 必须是可表示的正整数")
	}
	if options.idleTTL <= 0 {
		exitError("--idle-ttl 必须大于 0")
	}
	if options.insecureNoAuth {
		options.token = ""
	} else if options.token == "" {
		exitError("必须通过 GOHTTPX_TOKEN 或 --token 配置 token，开发环境可显式传入 --insecure-no-auth")
	}

	registry := newServer(options.token, options.maxBodyMiB<<20, options.idleTTL)
	httpServer := &http.Server{
		Addr:              net.JoinHostPort(options.host, strconv.Itoa(options.port)),
		Handler:           registry.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	interrupt := make(chan os.Signal, 1)
	shutdownDone := make(chan struct{})
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	go func() {
		defer close(shutdownDone)
		<-interrupt
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()

	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
	}
	registry.Close()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		exitError(err)
	}
}
