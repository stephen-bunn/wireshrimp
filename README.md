# Wireshrimp
Simple UI for Scapy3k packet sniffing

## Installing Requirements
Installing requirements is best done through a virtual environment.
This can be done by first installing the `virtualenv` and `virtualenvwrapper` modules on the local system using the `pip` utility.

```
pip install virtualenv virtualenvwrapper
```

Once these modules have been installed, the `virutalenvwrapper` module should have added the `workon` and `mkvritualenv` commands on the `PATH` of the system.
It may be necessary to also export a new environmental variable called `WORKON_HOME` which dictates the directory where created virtual environments will exist.
For example, the following command will make virtual environments exist under the directory `~/.envs/`:

```
export WORKON_HOME=~/.envs
```

By default, virtual environments should be stored under the directory `~/.virtualenvs/`.
The commands provided by `virtualenvwrapper` can be used to setup a Python 3.5 virtual environment for `wireshrimp` by using the following command:

```
mkvirtualenv wireshrimp --python=/usr/bin/python3.5
```

This will setup a new virtual environment called `wireshrimp` which should automatically be accessed.
You can tell if the virtual environment was automatically accessed by using the command `which python`.
This should list the alias for `python` under the new virtual environment rather than the default executable under the `/usr/bin` directory.
If you need to access the virtual environment, the `workon` command can be used to access an already existing virtual environment by using the following command:

```
workon wireshrimp
```

After you have accessed the virtual environment, all required dependency modules can be installed using `pip` and the `requirements.txt` file by using the following command:

```
pip install -r ./requirements.txt
```

If you wish to exit the virtual environment, you can use the `deactivate` command which is only accessible if inside a virtual environment.


## Running the Application
The application can be run by first building the executable using the following command once inside the created virtual environment:

```
python setup.py build
```

This will place an executable `wireshrimp` within a `./build/{arch}` directory which requires root privileges to execute:

```
sudo ./build/exe.linux-x86_64-3.5/wireshrimp
```