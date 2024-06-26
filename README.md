# keyval

Key-value (`keyval`) is a simple CLI utility to get and set keys and values.

This is my personal tool for keeping secrets on my local machine.

As of 2024-04-07, I consider this project done. I do not intend to make any major or minor feature additions.

## Prerequisites

- The environment variable KEYVAL_KEY needs to be set.
- Your user directory must not have an important `.keyval` dotfolder.

## Installation

1. Clone this repository.
2. Run `go build`.
3. Move the compiled `keyval` binary to somewhere on your PATH.

## Basic Usage

To set a key-value pair:

```shell
keyval set {your-key} {your-value}
```


To get a value:

```shell
keyval get {your-key}
```

To list the keys you've set:

```shell
# Main command
keyval list
# Or, as an alias
keyval ls
```


To delete a key and its value:

```shell
keyval delete {your-key}
```

To rename a key:

```shell
keyval mv {old-key-name} {new-key-name}
```

## Other features

To list the keys you've set that have a specific prefix:

```shell
# Also works with `keyval ls`
keyval list {prefix}
```

To set a key-value pair with a sensitive value:

```shell
keyval sset {your-key}
# You will then be prompted for a sensitive value
```

To set a key-value pair with the contents of a file as the value:

```shell
keyval fset {your-key} {your-file}
```

To set a key-value pair with stdin as the value:

```shell
{some-command} | keyval set {your-key}
```

To open the contents of a key-value pair in your terminal text editor:

```shell
keyval edit {your-key}
```

This will attempt to launch a program specified by an environment variable `EDITOR`. If no such variable is found, it will attempt to launch `vi`.

## Database management

Sometimes you may wish to move a database file or re-encrypt a database with a new key.

To dump a database:

```shell
# Dump the encrypted database to stdout
keyval dump
# Dump the encrypted database to a file
keyval dump {your-file}
```

To restore a database from a file dump:

```shell
keyval restore {your-file}
```

To export a database:

```shell
keyval export-decrypt {your-file}
```

Note that exporting will require a yes prompt because it decrypts the database.

To import a database:

```shell
keyval import-encrypt {your-file}
```

To merge two dumped databases:

```shell
keyval merge {file-1} {file-2} {output-file}
```

Note that these two files are the output of `keyval dump`.
