package main

type cliError struct {
	code int
	msg  string
}

func (e cliError) Error() string { return e.msg }
func (e cliError) ExitCode() int { return e.code }

func newCLIError(code int, msg string) error {
	return cliError{code: code, msg: msg}
}
