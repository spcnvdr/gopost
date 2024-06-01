# Gopost - A File Upload Server 

Gopost is a Go program for making file transfers. It can either serve files 
or accept multiple file uploads via POST. It imitates an unconfigured Apache 
server running on Ubuntu. Using the -s/--serve command line flag will instead 
serve files from the given directory (--serve=/home/user/Documents). Basic 
authentication and TLS is supported and can be enabled on the command line. 

I got the idea to make this program after learning about uploadserver 
[https://github.com/Densaugeo/uploadserver]. 

**WARNING**

While this server supports TLS and basic authentication, it may not be perfect.
I would recommend only using it on a secure or trusted network. Pick a good 
password when using basic authentication. Basic authentication is useless 
without TLS enabled too! If possible, use your own TLS certs instead of 
auto-generating self-signed certificates. Auto-generated/self-signed 
certificates created using the "-t/--tls" flag are good for 2 weeks from the 
day of creation.

**NOTE**

**You must run the program from within the cmd directory or the static resources
will not be found! Think templates and images.**

If using a self-signed TLS certificate, you may see errors logged such as

    http: TLS handshake error from 127.0.0.1:43434: remote error: tls: unknown certificate

This error message can be safely ignored as long as you intended to use a 
self-signed certificate. This error message is just informing you that the
client received a self-signed certificate when visiting the web page.

**Defaults**

Default settings are to serve on the first available IPv4 address (0.0.0.0) on 
port 8080 using HTTP. This can be changed with command line arguments.


**Usage**

Install Go and clone this repository

    git clone https://github.com/spcnvdr/gopost.git

Change into the directory inside the project

    cd ./gopost/

Build the program and change into the cmd directory

    make
    cd cmd

Optionally, change into the directory and build the program manually
    
    cd cmd
    go build ./cmd/main.go -o gopost

Run the program with --help to see available options. 

    ./gopost --help

The default option is to imitate an unconfigured Apache server and accept
file uploads to the current directory

    ./gopost

Generate self-signed TLS certs and serve FOLDER for downloading

    ./gopost -t -s FOLDER

Set up basic auth with existing TLS certs. Basic auth will 
interactively prompt for a password to avoid storing a password 
in .bash_history or other command line logs. 

    ./gopost -c cert.pem -k key.pem -u Bob

Use the -q/--query arguemnt to make the POST parameter used to accept uploads 
unpredicatable. This is an extra layer of security by obscurity to prevent 
someone from fuzzing the site and discovering upload functionality. Example
cURL command given too

    ./gopost -q sahdidnj -v 
    curl -X POST http://HOST:PORT -F 'sahdidnj=@./FILE.pdf' -v

This server accepts multiple file uploads from the command line 
using cURL. Add the --insecure option if using a self-signed certificate.

If using basic authentication, add the following to 
the commands: 

    -u login:password

Example of uploading to a server with self-signed certs

    curl -X POST https://IP:PORT/ -F 'files=@./myfile.txt' -F 'files=@./myfile.pdf' --insecure

or for when running plain HTTP:

    curl -X POST http://IP:PORT/ -F 'files=@./myfile.txt' -F 'files=@./myfile.pdf'


**To Do**

- [ ] Remove any unneeded functions/packages
- [ ] Add option to specify alternate destination directory for uploads
- [ ] Add Nginx default pages and option to impersonate Nginx
- [ ] Make response headers match exactly Apache/Nginx
- [ ] Show server address in 404 response? 
- [ ] Handle other error responses (400)


**Contributing**

Pull requests, new feature suggestions, and bug reports/issues are
welcome.


**License**

This project is licensed under the 3-Clause BSD License also known as the
*"New BSD License"* or the *"Modified BSD License"*. A copy of the license
can be found in the LICENSE file. A copy can also be found at the
[Open Source Institute](https://opensource.org/licenses/BSD-3-Clause)
