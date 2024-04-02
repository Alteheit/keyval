# keyval

Key-value (`keyval`) is a simple CLI utility to get and set keys and values.

This is my personal tool for keeping secrets on my local machine.

## Prerequisites

- The environment variable KEYVAL_KEY needs to be set.
- Your user directory must not have an important `.keyval` dotfolder.

## Installation

1. Clone this repository.
2. Run `go build`.
3. Move the compiled `keyval` binary to somewhere on your PATH.

## Usage

To set a key-value pair:

```shell
keyval set your-key your-value
```

To set a key-value pair with a sensitive value:

```shell
keyval sset your-key
# You will then be prompted for a sensitive value
```

To set a key-value pair with the contents of a file as the value:

```shell
keyval fset your-key your-file
```

To set a key-value pair with stdin as the value:

```shell
some-command | keyval set your-key
```

To get a value:

```shell
keyval get your-key
```

To list the keys you've set:

```shell
keyval list
```

To list the keys you've set that have a specific prefix:

```shell
keyval list {prefix}
```

To delete a key and its value:

```shell
keyval delete your-key
```
