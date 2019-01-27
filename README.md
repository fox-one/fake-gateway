# fake-gateway

## How It Works

FoxONE gateway接收来自用户的请求，经过简单处理后，添加相应的token等header，将请求发送至业务方的相应接口。业务方可使用token访问钱包服务。

转发的请求中，网关将为请求加上headers:

```text
Authorization: Bearer xxx
Fox-Merchant-ID: xxx
Fox-Member-ID: xxx
Fox-Wallet-ID: xxx
```

业务方的请求将分为三种，公共接口，需要访问钱包信息的接口，以及需要进行转账操作的接口。根据不同的接口，分别将请求发送至:

```text
/member/:service/p/*gw
/member/:service/u/*gw
/member/:service/pin/*gw
```

其中service由FoxONE为业务分配。如otc, exchange等。

## Build And Run

```shell
cd fake_gateway
go build
./fake_gateway --debug api -p 8081 -s http://locahost:8111
```