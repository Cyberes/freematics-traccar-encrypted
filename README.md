# freematics-traccar-encrypted

_A proxy to encrypt the Traccar Freematics protocol._

This is an implementation of the ChaCha20-Poly1305 algorithm into
the [Freematics vehicle tracker](https://freematics.com/products/freematics-one-plus-model-b/) for the Traccar server.

It consists of 2 parts:

1. A simple server written in Go that handles encryption and proxies messages to Traccar.
2. Modified firmware for the Freematics device that implements encryption.

The server is protocol-independant and only manages encryption, meaning it can serve other protocols besides Freematics.
It can also listen on multiple ports for multiple destinations.

[Inspired by soshial's great writeup on the Freematics device.](https://gist.github.com/soshial/d07919e0fac67f5501a38fe3c39be416)

### Install

#### Client

1. Run `server/generate-key.sh` script to generate your encryption key.
2. Open the modified firmware in Visual Studio Code with the PlatformIO extension.
3. Enter your encryption key under `CHACHA20_KEY` in `config.h`.
4. Upload the firmware to the device.

#### Server

1. Download the latest binary from [releases](https://git.evulid.cc/cyberes/freematics-traccar-encrypted/releases) or
   build it yourself using `./build.sh`.
2. Copy `config.sample.yml` to `config.yml`
3. Enter your encryption key in `config.yml` under `chacha_key`.
4. Fill our your forwarding destinations under `destinations`.
5. Start the server with `./freematics-encrypt --config config.yml`

A sample systemd service file is provided.