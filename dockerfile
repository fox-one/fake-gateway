# 源镜像
FROM golang:1.11.4-stretch

# 作者
LABEL maintainer="jiang@fox.one"

ENV GO111MODULE on

# 设置工作目录
WORKDIR $GOPATH/src/fake-gateway

# 复制依赖文件
COPY go.mod ./
COPY go.sum ./

# go安装依赖
RUN  go get -v ./...

# 将服务器的go工程代码加入到docker容器中
ADD . $GOPATH/src/fake-gateway

RUN cd $GOPATH/src/fake-gateway

# go构建可执行文件
RUN go build .

# 暴露端口
EXPOSE 8888

# 最终运行docker的命令
ENTRYPOINT  ["./fake-gateway", "api",  "-s", "http://ac20.d2labs.cn:8060/v1"]
