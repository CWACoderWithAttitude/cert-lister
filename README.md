# dev-container cert-lister

## What
I was tasked to check on various SSL/TLS certs.
This little app consumes a list of hostnames and produces a csv file with validity periods.

## How
Personally i use dev containers for nearly everything i do. You can do too.
But you don't now have to.

### W/O dev  containers

Just create a virtual environment, install the requirements and you should be good to go
Running the code plain use venv:
```shell
$ python3 -m venv .venv_cert-lister
$ source .venv_cert-lister/bin/activate
$ pip3 install -r requirements.txt
$ python cert-lister.py
...

```

## Links
* [Reading/Exporting csv files](https://docs.python.org/3.11/library/csv.html)
* [Python program to verify SSL Certificates](https://www.askpython.com/python/python-program-to-verify-ssl-certificates)