# xarmour
Split and process armoured text

## NAME
  xarmour - Split armoured data and process each one through a command.

## SYNOPSIS
  xarmour [-t times] [-v] [-h] [--] command [options]

## DESCRIPTION

  The xarmour command parses multiple armoured text blocks containing
  PEM encoded or PGP armoured data, and passes each one to the command
  specified via stdin.

  All text outside the armoured text block is ignored.

## OPTIONS
-  -t, --times t  Number of times command must be successful for xarmour to
                 return success. If unset, xarmour will give up on first
                 failure.
-  -h, --help     Display this help message.

-  -v, --version  Display the version number.

## ENVIRONMENT
  The xarmour tool adds the following environment variables, which can be
  used by scripts or for further processing.

-  XARMOUR_INDEX  Index of armoured text, starting at zero.
-  XARMOUR_COUNT  Command successes so far.
-  XARMOUR_TIMES  Times, if set.
-  XARMOUR_LABEL  Label of the armoured text.

## RETURN VALUE
  The xarmour tool returns the return code from the
  first executable to fail.

  If the executable was interrupted with a signal, the return
  code is the signal number plus 128.

  If the executable could not be executed, or if the options
  are invalid, the status 1 is returned.

  If the times option is specified, we count the number of times the command
  was successful. If the threshold was reached, we return 0. If the threshold
  was not reached, we return 1. In this mode we process all armoured data even
  if we could end early.

## EXAMPLES
  In this trivial example, we print the label of each armoured text found.

	~$ cat chain.pem | xarmour -- printenv XARMOUR_LABEL

  In this basic example, we split a series of detached PGP signatures,
  passing each signature to the gpg command. If we find two valid signatures,
  we succeed.

	~$ cat original_file.asc | xarmour -t 2 -- gpg --verify - original_file

## AUTHOR
  Graham Leggett <minfrin@sharp.fm>
