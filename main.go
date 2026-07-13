package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"
)

func main() {
	host := flag.String("host", "127.0.0.1", "监听主机")
	port := flag.Int("port", 9876, "监听端口")
	token := flag.String("token", os.Getenv("GOHTTPX_TOKEN"), "Bearer token")
	insecureNoAuth := flag.Bool("insecure-no-auth", false, "禁用鉴权（仅限开发）")
	allowNonLoopback := flag.Bool("allow-non-loopback", false, "允许监听非 loopback 地址")
	maxBodyMiB := flag.Int64("max-body-mib", 48, "最大目标响应正文（MiB）")
	idleTTL := flag.Duration("idle-ttl", 24*time.Hour, "空闲会话生存时间")
	flag.Parse()

	ip := net.ParseIP(*host)
	if !*allowNonLoopback && *host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Fatal("拒绝监听非 loopback 地址；如确有需要，请显式传入 --allow-non-loopback")
	}
	if *port < 1 || *port > 65535 {
		log.Fatal("端口必须在 1 到 65535 之间")
	}
	if *maxBodyMiB < 1 || *maxBodyMiB > (1<<63-1)/(1<<20) {
		log.Fatal("--max-body-mib 必须是可表示的正整数")
	}
	if *idleTTL <= 0 {
		log.Fatal("--idle-ttl 必须大于 0")
	}
	if *insecureNoAuth {
		*token = ""
		log.Print("警告：已禁用控制 API 鉴权")
	} else if *token == "" {
		log.Fatal("必须通过 GOHTTPX_TOKEN 或 --token 配置 token，开发环境可显式传入 --insecure-no-auth")
	}

	registry := newServer(*token, *maxBodyMiB<<20, *idleTTL)
	httpServer := &http.Server{
		Addr:              net.JoinHostPort(*host, strconv.Itoa(*port)),
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
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("优雅关闭失败: %v", err)
		}
	}()

	log.Printf("GoHTTPX 监听 %s", httpServer.Addr)
	err := httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
	}
	registry.Close()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
