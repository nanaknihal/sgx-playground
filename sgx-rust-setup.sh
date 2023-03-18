curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install nightly
rustup target add x86_64-fortanix-unknown-sgx --toolchain nightly
#Ubuntu 16.04/18.04
echo "deb https://download.fortanix.com/linux/apt xenial main" | sudo tee -a /etc/apt/sources.list.d/fortanix.list >/dev/null
curl -sSL "https://download.fortanix.com/linux/apt/fortanix.gpg" | sudo -E apt-key add -
sudo apt-get update
sudo apt-get install intel-sgx-dkms
#AESM
sudo apt install docker.io
#note: changed this to /dev/sgx from /dev/isgx in instructions:
sudo docker run --detach --restart always --device /dev/sgx --volume /var/run/aesmd:/var/run/aesmd --name aesmd fortanix/aesmd
sudo apt-get install pkg-config libssl-dev protobuf-compiler
cargo install fortanix-sgx-tools sgxs-tools
# Check whether sgx working
curl --proto '=https' --tlsv1.2 -sSf https://download.fortanix.com/sgx-detect/ubuntu16.04/sgx-detect -O
chmod +x ./sgx-detect
./sgx-detect

