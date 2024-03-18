# keyval

Key-value (`keyval`) is a simple CLI utility to get and set keys and values.

This is my personal tool for keeping secrets on my local machine.

The environment variable KEYVAL_KEY needs to be set.

## Usage

To set a value:

```shell
keyval set your-key your-value
```

To get a value:

```shell
keyval get your-key
```

To list the keys you've set:

```shell
keyval list
```

To delete a key and its value:

```shell
keyval delete your-key
```
