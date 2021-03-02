# Arch Vulnerability Group auditor
avg-audit will check currently installed packages on Arch Linux based systems against https://security.archlinux.org/issues/. This is very similar to pacaudit and archsecure and arch-audit, however it allows for custom formatting of the fields and has all the same features (except the nagios plugin in pacaudit, which I plan to add). It has a couple of other minor improvements as well, such as testing against all known security vulnerabilities including fixed ones, which could be useful in case of outdated software. I also have other features in mind like running as a service, or alongside an update utility.

The C version is a work in progress.

# Installation
For the bash script

`$ wget https://raw.githubusercontent.com/i34/avg-audit/master/avg-audit && chmod +x avg-audit`

For the C program
```
$ yay -S yajl aur/alpm_octopi_utils
$ wget https://raw.githubusercontent.com/644/avg-audit/master/avg-audit.c
$ gcc -o avg-audit avg-audit.c $(pkg-config --cflags --libs glib-2.0 libalpm libalpm_octopi_utils) -lyajl -lcurl -Wpedantic -O3
```

# Usage
For the bash script
```
    -h    Show this help message
    -a    Show all fields
          This is equal to -f name,packages,status,severity,type,affected,fixed,ticket,issues
    -f    Custom format, e.g. -f packages,affected,severity
    -v    Show all vulnerable packages, not just ones on the system
    -c    Colorize output
    -t    Test against all packages, including fixed ones
    -l    Link to the full AVG URL
    -n    Do not count vulnerable/listed packages at the end
    -b    Alternative database location

Fields:
    name        Link to the Arch Vulnerability Group number
    packages    List of the affected packages
    status      Shows whether it is fixed or not
    severity    From Critical, High, Medium, to Low
    type        Short description on the type of attack
    affected    Version number of the affected package
    fixed       Version number of the fixed package
    ticket      Ticket number for bugs.archlinux.org
    issues      List of related CVEs
```

For the C program
```
$ ./avg-audit | column -s, -t
```

# Dependencies
jq, curl, pacman, yay, yajl, alpm_octopi_utils

# Example
![example.png](example.png)

# License
MIT
