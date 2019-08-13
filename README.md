CertificationCenter
====================

### About CertificationCenter
The CertificationCenter is a web interface for working with the console utilities openssl and easy-rsa.

### What you need to install and launch CertificationCenter
 * Linux distribution
 * Python3
 * easy-rsa (version 2)

### Installation
Download the archive with the program in a directory convenient for you and unpack:
```
    unzip CertificationCenter-master.zip
```

Install Easy-RSA:
```
    sudo apt-get install easy-rsa
```

Copy easy-rsa in your folder:
```
    cp -r /usr/share/easy-rsa /home/user/Загрузки/CertificationCenter-master/easy-rsa
```

Configure the configuration file:
```
    cd CertificationCenter-master/easy-rsa
    cp openssl-1.0.0 openssl.cnf
    nano openssl.cnf
```

Then specify the variable file and create a certification authority:
``` 
    source ./vars
    ./clean-all
    ./build-ca
```

and then enter fields.

Create a virtual environment and install libraries:

```
    cd ..
    python3 -m venv venv
    source venv/bin/activate
    pip install pycryptodome pyopenssl flask pyyaml Flask-WTF flask-bootstrap
```

Run CertificationCenter:
```
    flask run
```

You can see the result by typing 127.0.0.1:5000 in your browser.
