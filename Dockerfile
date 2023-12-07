FROM golang
WORKDIR /
RUN git clone https://github.com/truekonrads/danglingcname.git && cd danglingcname && go build .
#ENV DNSDB_KEY="XXXXXXXXXXXXXXXXXXXXXXX"
ENTRYPOINT ["/danglingcname/danglingcname"]
