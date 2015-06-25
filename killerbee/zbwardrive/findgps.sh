#!/bin/bash

for sysdevpath in $(find /sys/bus/usb/devices/usb*/ -name dev); do
    (
        syspath="${sysdevpath%/dev}"
        devname="$(udevadm info -q name -p $syspath)"
        eval "$(udevadm info -q property --export -p $syspath)"
	if [[ "$ID_SERIAL" = *"Prolific"* ]]
	then 
		if [[ "$devname" = *"tty"* ]]
		then
			echo "/dev/$devname"        
		fi
	fi
    )

# echo "/dev/$devname - $ID_SERIAL"

done
