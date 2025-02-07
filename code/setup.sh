#!/bin/bash

# Ensure the script is executed with root privileges
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Please use 'sudo' to execute it."
  exec sudo "$0" "$@"
fi


# Define variables for directories and visual indicators
HOME_DIR=$(eval echo "~$SUDO_USER")              # Home directory of the user running the script
DESTINY_DIR="$HOME_DIR/.dataseeker"              # Destination directory for the application
OK='[  \033[0;32mOK\033[0m  ] '                  # Visual indicator for successful operations
ERROR='[ \033[0;31mERROR\033[0m ]'               # Visual indicator for errors
WARNING='[\033[38;5;214mWARNING\033[0m]'         # Visual indicator for warnings


# Install required system packages: pip and python3-venv
printf "Installing pip and python3-venv..."
if sudo apt install python3-venv python3-pip -y > /dev/null 2>&1; then
    printf "\r${OK} pip and python3-venv installed\n"
else
    printf "\r${ERROR} Failed to install required packages. Exiting.\n"
    exit 1
fi


# Create a wrapper script to execute the application
printf "Creating wrapper script..."
WRAPPER_FILE="dataseeker"
cat <<'EOF' > "/usr/bin/$WRAPPER_FILE"
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  exec sudo "$0" "$@"
fi
HOME_DIR=$(eval echo "~$SUDO_USER")
$HOME_DIR/.dataseeker/seeker/bin/python3 $HOME_DIR/.dataseeker/main.py "$@"
EOF
sudo chmod +x "/usr/bin/$WRAPPER_FILE"
printf "\r${OK} Wrapper script created\n"


# Define script source and target directories
SCRIPTS_DIR=$(dirname "$(realpath "$0")")        # Directory containing the current script
SOURCE_DIR=${SCRIPTS_DIR%/*}                     # Parent directory of the script's directory
FILES=("arg_parser.py"                           # List of required Python scripts
       "banner_grabbing.py"
       "display.py"
       "main.py"
       "network.py"
       "os_db.txt"
       "os_fingerprint.py"
       "packets.py"
       "port_scanner.py"
       "sys_command.py"
       )


# Create the destination directory for the application
printf "Creating directory..."
mkdir -p "$DESTINY_DIR"


# Verify if all required files exist and copy them to the destination directory
FILES_NOT_FOUND=""
for file in "${FILES[@]}"; do
    if [ ! -e "$SCRIPTS_DIR/$file" ]; then
        FILES_NOT_FOUND="$FILES_NOT_FOUND $file"
    fi
done


# If no files are missing, copy them to the destination
if [ -z "$FILES_NOT_FOUND" ]; then
    for file in "${FILES[@]}"; do
        cp "$SCRIPTS_DIR/$file" "$DESTINY_DIR"
    done
else
    printf "\n${ERROR} Files not found: $FILES_NOT_FOUND\n"
    exit 1
fi
printf "\r${OK} Directory created\n"


# Copy the LICENSE file if it exists
if [ -e "$SOURCE_DIR/LICENSE" ]; then
    cp "$SOURCE_DIR/LICENSE" "$DESTINY_DIR" 2> /dev/null
else
    printf "${WARNING} LICENSE not found\n"
fi


# Create a Python virtual environment
printf "Creating virtual environment..."
if python3 -m venv "$DESTINY_DIR/seeker" > /dev/null 2>&1; then
    printf "\r${OK} Virtual environment created successfully\n"
else
    printf "\r${ERROR} Failed to create virtual environment. Exiting.\n"
    exit 1
fi


# Activate the virtual environment
source "$DESTINY_DIR/seeker/bin/activate"


# Install Scapy in the virtual environment
printf "Installing Scapy within virtual environment..."
if pip install scapy > /dev/null 2>&1; then
    printf "\r${OK} Scapy installed within virtual environment\n"
else
    printf "\r${ERROR} Failed to install Scapy within virtual environment. Exiting.\n"
    exit 1
fi


# Deactivate the virtual environment
deactivate


# Display installation completion message
echo -e "\033[0;32mINSTALLATION COMPLETED\033[0m"
