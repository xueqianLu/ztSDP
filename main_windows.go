/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 ZtSDP LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/xueqianLu/ztSDP/device"
	"github.com/xueqianLu/ztSDP/ipc"

	"github.com/xueqianLu/ztSDP/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]

	fmt.Fprintln(os.Stderr, "Warning: this is a test program for Windows, mainly used for debugging this Go package. For a real ZtSDP for Windows client, the repo you want is <https://git.zx2c4.com/ztSDP-windows/>, which includes this code as a module.")

	logger := device.NewLogger(
		device.LogLevelDebug,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	logger.Info.Println("Starting ztSDP-go version", device.ZtSDPGoVersion)
	logger.Debug.Println("Debug log enabled")

	tun, err := tun.CreateTUN(interfaceName)
	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	} else {
		logger.Error.Println("Failed to create TUN device:", err)
		os.Exit(ExitSetupFailed)
	}

	device := device.NewDevice(tun, logger)
	device.Up()
	logger.Info.Println("Device started")

	uapi, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		logger.Error.Println("Failed to listen on uapi socket:", err)
		os.Exit(ExitSetupFailed)
	}

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()
	logger.Info.Println("UAPI listener started")

	// wait for program to terminate

	signal.Notify(term, os.Interrupt)
	signal.Notify(term, os.Kill)
	signal.Notify(term, syscall.SIGTERM)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Info.Println("Shutting down")
}
