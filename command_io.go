package main

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

type commandIO struct {
	in  io.Reader
	out io.Writer
	err io.Writer
}

func commandStreams(cmd *cobra.Command) commandIO {
	return commandIO{in: cmd.InOrStdin(), out: cmd.OutOrStdout(), err: cmd.ErrOrStderr()}
}

func streamFD(stream any) int {
	if file, ok := stream.(*os.File); ok {
		return int(file.Fd())
	}
	return -1
}
