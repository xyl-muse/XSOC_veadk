1.环境变量中定义：CAASM_BASE_URL=https://caasm.longi.com 
    实际的资产查询工具中写的caasm查询接口url有问题，这块出错需要再确认tool写的api对不对

2.CORPLINK_BASE_URL=https://feilian.longi.com:10443/api/  #{base_url}/open/v1/device/search，这里应该加api;
    corplink系统的url格式是/api/open/v1/user/batch_get_id，我们的代码里环境变量多数定义是只定义域名，目录在工具中加载，这块/api写在变量里面，有点出入
    规范的写法，要么所有的env都带齐目录写好url，要么所有env都不带目录
    本项目中规范应该是env都不带目录，因为某一个系统的接口url太多了，如果都写死在env，后面的工具集就没办法展开