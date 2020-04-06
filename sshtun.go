package main

import (
        "io"
        "log"
        "fmt"
        "github.com/unknwon/goconfig"
        "github.com/gliderlabs/ssh"
        "os"
        "strconv"
        "time"

)
type Conf struct {
	ipaddr string
	port int
    minport uint32
    maxport uint32
    onlylocalbind bool
    auth bool
}

var (
	DeadlineTimeout = 30 * time.Second
	IdleTimeout     = 10 * time.Second
)


func main() {
  var conf Conf

    cfg, err := goconfig.LoadConfigFile("sshtun.ini")
    if err != nil {
        fmt.Printf("Fail to read file: %v", err)
        os.Exit(1)
    }
    users, err := goconfig.LoadConfigFile("sshu.ini")
    if err != nil {
        fmt.Printf("Fail to read file: %v", err)
        os.Exit(1)
    }

   if conf.ipaddr, err = cfg.GetValue("sshtun","ipaddr"); err == nil {
		 conf.ipaddr = "0.0.0.0"
	}
   if conf.port, err = cfg.Int("sshtun","port"); err == nil {
		 conf.port = conf.port
	}else{
        conf.port = 1884
    }
    if mp, err := cfg.Int("sshtun","minport"); err == nil {
		 conf.minport = uint32(mp)
	}else{
	     conf.minport = 20000
    }
    if mp, err := cfg.Int("sshtun","maxport"); err == nil {
		 conf.maxport = uint32(mp)
    }else{
	 conf.maxport = 50000
    }

    if conf.onlylocalbind, err = cfg.Bool("sshtun","onlylocalbind"); err == nil {
		 conf.onlylocalbind = true
	}   

    if conf.auth, err = cfg.Bool("sshtun","auth"); err == nil {
		 conf.auth = true
	} 

    fmt.Println(conf)

        log.Println("starting ssh ",conf.ipaddr,":", conf.port, "...")

        forwardHandler := &ssh.ForwardedTCPHandler{}

        server := ssh.Server{
                MaxTimeout:  DeadlineTimeout,
                IdleTimeout: IdleTimeout,
                Addr: conf.ipaddr+":"+strconv.Itoa(conf.port),
                Handler: ssh.Handler(func(s ssh.Session) {
                        log.Println("User: ", s.User())
                        io.WriteString(s, "enable tun forward\n")
                        select {}
                }),
                PasswordHandler: ssh.PasswordHandler(func(ctx ssh.Context, pass string) bool {
                    log.Println("Auth: ", ctx.User(), pass)
                    upass,_:=users.GetValue(ctx.User(),"passwd")
                    if upass==pass {
                        return true
                    } else {
                        return false
                    }
                }),
                LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
					alocal,_:=users.Bool(ctx.User(),"allowlocal")
					if !alocal {
						log.Println("Local not allowed ", ctx.User())
						return false
					}
                        if conf.onlylocalbind {
                            if dhost != "127.0.0.1" {
                                log.Println("Only local bind host: ", dhost, dport)
                                return false
                            } else {
                                log.Println("Accept forward: ", dhost, dport, ctx.User())
                                return true
                            }
                        } else {
                            log.Println("Accept forward: ", dhost, dport, ctx.User())
                            return true
                        }
                }),
                ChannelHandlers: map[string]ssh.ChannelHandler{
                    "direct-tcpip": ssh.DirectTCPIPHandler,
                    "session":      ssh.DefaultSessionHandler,
                },
                ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
                        aremote,_:=users.Bool(ctx.User(),"allowremote")
                        if !aremote {
                            log.Println("Remote not allowed ", ctx.User())
                            return false
                        }
                        if conf.onlylocalbind {
                            if host != "127.0.0.1" {
								if host != "" {
                                	log.Println("Only local bind host trying: ", host)
									return false
								}
                            }
                        }
                        if port > conf.minport {
                            if port < conf.maxport {
                            log.Println("attempt to bind", host, port, "granted", ctx.RemoteAddr())
                                return true
                            }else{
                                log.Println("attempt to bind", host, port, " not granted", ctx.RemoteAddr())
                                return false
                            }
                        } else {
                            log.Println("attempt to bind", host, port, "not granted", ctx.RemoteAddr())
                            return false
                        }
                }),
                RequestHandlers: map[string]ssh.RequestHandler{
                        "tcpip-forward":        forwardHandler.HandleSSHRequest,
                        "cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
                },
        }
        log.Fatal(server.ListenAndServe())
}
