# INSTAL

wget https://raw.githubusercontent.com/baconfig/ahmadtnl/main/cekdpkg.sh && chmod +x cekdpkg.sh && ./cekdpkg.sh


rm cekdpkg.sh && apt update && apt install -y bzip2 gzip coreutils screen curl unzip && wget https://raw.githubusercontent.com/baconfig/ahmadtnl/main/setup.sh && chmod +x setup.sh && sed -i -e 's/\r$//' setup.sh && screen -S setup ./setup.sh
