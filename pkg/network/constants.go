package network

import "time"

const (
    connTimeout   = 30 * time.Second
    maxMsgSize    = 1024 * 1024 // 1MB
    readTimeout   = 30 * time.Second
    writeTimeout  = 30 * time.Second
)