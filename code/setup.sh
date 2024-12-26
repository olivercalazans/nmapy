#!/bin/bash

FILE="dataseeker"
DICT="$HOME/.dataseeker/"

echo "#!/bin/bash" > $FILE
echo "sudo $HOME/.dataseeker/code/seeker/bin/python3 $HOME/.dataseeker/code/main.py \"\$@\"" >> $FILE

sudo mv $FILE /usr/bin

sudo chmod +x /usr/bin/$FILE

mkdir $DICT && mkdir "$DICT/code/"

mv ../code/* "$DICT/code"
mv ../* $DICT 2> /dev/null

sudo apt install python3-venv python3-pip -y

python3 -m venv "$DICT/code/seeker"

source "$DICT/code/seeker/bin/activate"

pip install scapy

deactivate

rm -rf ../../dataseeker
