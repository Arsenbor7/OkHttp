OkHttp

[TOC]



## 1.OkHttp总体架构



大致可以分为以下几层：

Interface——接口层：接受网络访问请求
Protocol——协议层：处理协议逻辑
Connection——连接层：管理网络连接，发送新的请求，接收服务器访问
Cache——缓存层：管理本地缓存
I/O——I/O层：实际数据读写实现
Inteceptor——拦截器层：拦截网络访问，插入拦截逻辑

![image-20210723160303569](C:\Users\shishenpeng\AppData\Roaming\Typora\typora-user-images\image-20210723160303569.png)

### 1.1每层的含义

#### 1.1.1Interface——接口层:

​	接口层接收用户的网络访问请求(同步/异步)，发起实际的网络访问。OKHttpClient是OkHttp框架的客户端，更确切的说是一个用户面板。用户使用OkHttp进行各种设置，发起各种网络请求都是通过OkHttpClient完成的。每个OkHttpClient内部都维护了属于自己的任务队列，连接池，Cache，拦截器等，所以在使用OkHttp作为网络框架时应该全局共享一个OkHttpClient实例。

​	Call描述了一个实际的访问请求，用户的每一个网络请求都是一个Call实例，Call本身是一个接口，定义了Call的接口方法，在实际执行过程中，OkHttp会为每一个请求创建一个RealCall，即Call的实现类。

​	Dispatcher是OkHttp的任务队列，其内部维护了一个线程池，当有接收到一个Call时，Dispatcher负责在线程池中找到空闲的线程并执行其execute方法。

#### 1.1.2Protocol——协议层:处理协议逻辑

​	Protocol层负责处理协议逻辑，OkHttp支持Http1/Http2/WebSocket协议，并在3.7版本中放弃了对Spdy协议，鼓励开发者使用Http/2。

#### 1.1.3Connection——连接层：管理网络连接，发送新的请求，接收服务器访问

​	连接层顾名思义就是负责网络连接，在连接层中有一个连接池，统一管理所有的Scoke连接，当用户发起一个新的网络请求是，OKHttp会在连接池找是否有符合要求的连接，如果有则直接通过该连接发送网络请求；否则新创建一个网络连接。

​	RealConnection描述一个物理Socket连接，连接池中维护多个RealConnection实例，由于Http/2支持多路复用，一个RealConnection，所以OKHttp又引入了StreamAllocation来描述一个实际的网络请求开销（从逻辑上一个Stream对应一个Call，但在实际网络请求过程中一个Call常常涉及到多次请求。如重定向，Authenticate等场景。所以准确地说，一个Stream对应一次请求，而一个Call对应一组有逻辑关联的Stream），一个RealConnection对应一个或多个StreamAllocation，所以StreamAllocation，是以StreamAllocation可以看做是RealConenction的计数器，当RealConnection的引用计数变为0，且长时间没有被其他请求重新占用就将被释放。

#### 1.1.4Cache——缓存层：管理本地缓存

​	Cache层负责维护请求缓存，当用户的网络请求在本地已有符合要求的缓存时，OKHttp会直接从缓存中返回结果，从而节省 网络开销。

#### 1.1.5Inteceptor——拦截器层：拦截网络访问，插入拦截逻辑

​	拦截器层提供了一个类AOP接口，方便用户可以切入到各个层面对网络访问进行拦截并执行相关逻辑。



## 2.OkHttp发送请求

​	一个简单的同步请求的OkHttp的示例。

```java
new Thread(new Runnable() {
            @Override
            public void run() {
                try {

                    OkHttpClient client = new OkHttpClient();
                    Request request = new Request.Builder().url("http://www.baidu.com")
                            .build();

                    try {
                        Response response = client.newCall(request).execute();
                        if (response.isSuccessful()) {
                            System.out.println("成功");
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();
```



### 2.1OkHttpClient()类

```java
public OkHttpClient() {
    this(new Builder());
  }

  OkHttpClient(Builder builder) {
    this.dispatcher = builder.dispatcher;//调度器
    this.proxy = builder.proxy;//代理
    this.protocols = builder.protocols;//默认支持的Http协议版本
    this.connectionSpecs = builder.connectionSpecs;//OKHttp连接（Connection）配置
    this.interceptors = Util.immutableList(builder.interceptors);
    this.networkInterceptors = Util.immutableList(builder.networkInterceptors);
    this.eventListenerFactory = builder.eventListenerFactory;//一个Call的状态监听器
    this.proxySelector = builder.proxySelector;//使用默认的代理选择器
    this.cookieJar = builder.cookieJar;//默认是没有Cookie的；
    this.cache = builder.cache;//缓存
    this.internalCache = builder.internalCache;
    this.socketFactory = builder.socketFactory;//使用默认的Socket工厂产生Socket；

    boolean isTLS = false;
    for (ConnectionSpec spec : connectionSpecs) {
      isTLS = isTLS || spec.isTls();
    }

    if (builder.sslSocketFactory != null || !isTLS) {
      this.sslSocketFactory = builder.sslSocketFactory;
      this.certificateChainCleaner = builder.certificateChainCleaner;
    } else {
      X509TrustManager trustManager = systemDefaultTrustManager();
      this.sslSocketFactory = systemDefaultSslSocketFactory(trustManager);
      this.certificateChainCleaner = CertificateChainCleaner.get(trustManager);
    }

    this.hostnameVerifier = builder.hostnameVerifier;//安全相关的设置
    this.certificatePinner = builder.certificatePinner.withCertificateChainCleaner(
        certificateChainCleaner);
    this.proxyAuthenticator = builder.proxyAuthenticator;
    this.authenticator = builder.authenticator;
    this.connectionPool = builder.connectionPool;//连接池
    this.dns = builder.dns;//域名解析系统 domain name -> ip address；
    this.followSslRedirects = builder.followSslRedirects;
    this.followRedirects = builder.followRedirects;
    this.retryOnConnectionFailure = builder.retryOnConnectionFailure;
    this.connectTimeout = builder.connectTimeout;
    this.readTimeout = builder.readTimeout;
    this.writeTimeout = builder.writeTimeout;
    this.pingInterval = builder.pingInterval;// 这个和WebSocket有关。为了保持长连接，我们必须间隔一段时间发送一个ping指令进行保活；

    if (interceptors.contains(null)) {
      throw new IllegalStateException("Null interceptor: " + interceptors);
    }
    if (networkInterceptors.contains(null)) {
      throw new IllegalStateException("Null network interceptor: " + networkInterceptors);
    }
  }
```

​	在我们定义了请求对象后，我们需要生成一个Call对象，该对象代表一个准备被执行的请求，Call是可以被取消的，一个Call只能被执行一次.
​	从newCall进入源码

```java
  /**
   * Prepares the {@code request} to be executed at some point in the future.
   */
  @Override public Call newCall(Request request) {
    return RealCall.newRealCall(this, request, false /* for web socket */);
  }
```

​	继续进入newReakCall中

```java
final class RealCall implements Call {
  final OkHttpClient client;
  final RetryAndFollowUpInterceptor retryAndFollowUpInterceptor;

  /**
   * There is a cycle between the {@link Call} and {@link EventListener} that makes this awkward.
   * This will be set after we create the call instance then create the event listener instance.
   */
  private EventListener eventListener;

  /** The application's original request unadulterated by redirects or auth headers. */
  final Request originalRequest;
  final boolean forWebSocket;

  // Guarded by this.
  private boolean executed;
	/**
	*RealCall对象会持有OkHttpClient对象，Request对象的引用，并且还实例化了拦截器链中的第一个拦截器RetryAndFollowUpInterceptor，也就是重试和重定向拦截器
	*/
  private RealCall(OkHttpClient client, Request originalRequest, boolean forWebSocket) {
    this.client = client;
    this.originalRequest = originalRequest;
    this.forWebSocket = forWebSocket;
    this.retryAndFollowUpInterceptor = new RetryAndFollowUpInterceptor(client, forWebSocket);
  }

  static RealCall newRealCall(OkHttpClient client, Request originalRequest, boolean forWebSocket) {
    // Safely publish the Call instance to the EventListener.
    RealCall call = new RealCall(client, originalRequest, forWebSocket);
    call.eventListener = client.eventListenerFactory().create(call);
    return call;
  }
    .....
}
```

​	可以看出在OkHttp中实际生产的是一个Call的实现类RealCall。

### 2.2Dispatcher类

​	Dispatcher类负责异步任务的请求策略。

```java
public final class Dispatcher {
  private int maxRequests = 64;
    //每个主机的最大请求数,如果超过这个数，那么新的请求就会被放入到readyAsyncCalls队列中
  private int maxRequestsPerHost = 5;
     //是Dispatcher中请求数量为0时的回调，这儿的请求包含同步请求和异步请求，该参数默认为null。 
  private @Nullable Runnable idleCallback;

  /** Executes calls. Created lazily. */
  private @Nullable ExecutorService executorService;
    //任务队列线程池

  /** Ready async calls in the order they'll be run. */
  private final Deque<AsyncCall> readyAsyncCalls = new ArrayDeque<>();
    //待执行异步任务队列

  /** Running asynchronous calls. Includes canceled calls that haven't finished yet. */
  private final Deque<AsyncCall> runningAsyncCalls = new ArrayDeque<>();
	//运行中的异步任务队列
  /** Running synchronous calls. Includes canceled calls that haven't finished yet. */
  private final Deque<RealCall> runningSyncCalls = new ArrayDeque<>();
	  //运行中同步任务队列
  public Dispatcher(ExecutorService executorService) {
    this.executorService = executorService;
  }

  public Dispatcher() {
  }
  public synchronized ExecutorService executorService() {
    if (executorService == null) {
      executorService = new ThreadPoolExecutor(0, Integer.MAX_VALUE, 60, TimeUnit.SECONDS,
          new SynchronousQueue<Runnable>(), Util.threadFactory("OkHttp Dispatcher", false));
    }
    return executorService;
  }
```

​	查看ThreadPoolExecutor类

```java
    public ThreadPoolExecutor(int corePoolSize,
                              int maximumPoolSize,
                              long keepAliveTime,
                              TimeUnit unit,
                              BlockingQueue<Runnable> workQueue,
                              ThreadFactory threadFactory) {
        this(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue,
             threadFactory, defaultHandler);
    }
```

​	corePoolSize :核心线程数，默认情况下核心线程会一直存活
​	maximumPoolSize: 线程池所能容纳的最大线程数。超过这个数的线程将被阻塞。
​	keepAliveTime: 非核心线程的闲置超时时间，超过这个时间就会被回收。
​	unit: keepAliveTime的单位。
​	workQueue: 线程池中的任务队列。
​	threadFactory: 线程工厂，提供创建新线程的功能
corePoolSize设置为0表示一旦有闲置的线程就可以回收。容纳最大线程数设置的非常大，但是由于受到maxRequests的影响，并不会创建特别多的线程。60秒的闲置时间。

### 2.3同步请求的执行流程

```java
 new Thread(new Runnable() {
            @Override
            public void run() {
                try {

                    OkHttpClient client = new OkHttpClient();
                    Request request = new Request.Builder().url("http://www.baidu.com")
                            .build();

                    try {
                        Response response = client.newCall(request).execute();
                        if (response.isSuccessful()) {
                            System.out.println("成功");
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();

```

​	在同步请求里，调用了 client.newCall(request).execute()的方法，在上文说过newCall返回的是一个RealCall对象，所以execute的实现在RealCall中

```java
//RealCall类中
@Override public Response execute() throws IOException {
    //设置execute标志为true，即同一个Call只允许执行一次，执行多次就会抛出异常
  synchronized (this) {
    if (executed) throw new IllegalStateException("Already Executed");
    executed = true;
  }
   //重定向拦截器相关
  captureCallStackTrace();
  eventListener.callStart(this);
  try {
      //调用dispatcher()获取Dispatcher对象，调用executed方法
    client.dispatcher().executed(this);
       //getResponseWithInterceptorChain拦截器链
    Response result = getResponseWithInterceptorChain();
    if (result == null) throw new IOException("Canceled");
    return result;
  } catch (IOException e) {
    eventListener.callFailed(this, e);
    throw e;
  } finally {
      //调用Dispatcher的finished方法
    client.dispatcher().finished(this);
  }
}
```

​	进入 captureCallStackTrace()；

```java
 private void captureCallStackTrace() {
    Object callStackTrace = Platform.get().getStackTraceForCloseable("response.body().close()");
    retryAndFollowUpInterceptor.setCallStackTrace(callStackTrace);
  }
```

​	查看dispatcher的finished方法

```java
//Dispatcher类中
  void finished(AsyncCall call) {
  //异步请求结束时调用此方法
  finished(runningAsyncCalls, call, true);
}

/** Used by {@code Call#execute} to signal completion. */
void finished(RealCall call) {
  //同步请求结束时调用此方法
  finished(runningSyncCalls, call, false);
}
/**
*将执行完毕的call从相应的队列移除
*/
private <T> void finished(Deque<T> calls, T call, boolean promoteCalls) {
    int runningCallsCount;
    Runnable idleCallback;
    synchronized (this) {
       //移出请求，如果不能移除，则抛出异常
      if (!calls.remove(call)) throw new AssertionError("Call wasn't in-flight!");

      //传入参数为flase，不执行这个语句
      if (promoteCalls) promoteCalls();
	
      //unningCallsCount统计目前还在运行的请求
      runningCallsCount = runningCallsCount();

      //请求数为0时的回调
      idleCallback = this.idleCallback;
    }

    //如果请求数为0，且idleCallback不为NULL，回调idleCallback的run方法。
    if (runningCallsCount == 0 && idleCallback != null) {
      idleCallback.run();
    }
  }
```

​	查看runningCallsCount()方法

```java
  public synchronized int runningCallsCount() {
    return runningAsyncCalls.size() + runningSyncCalls.size();
  }
```

### 2.4异步请求的执行流程

```java
 private void getDataAsync() {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
                .url("http://www.baidu.com")
                .build();
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
            }
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if(response.isSuccessful()){//回调的方法执行在子线程。
                    Log.d("OkHttp","获取数据成功了");
                    Log.d("OkHttp","response.code()=="+response.code());
                	 Log.d("OkHttp","response.body().string()=="+response.body().string());
                }
            }
        });
    }
```

​	和同步请求类似，client.newCall(request).enqueue的方法，所以enqueue的实现在RealCall中

```java
  @Override public void enqueue(Callback responseCallback) {
       //设置exexuted参数为true，表示不可以执行两次。
    synchronized (this) {
      if (executed) throw new IllegalStateException("Already Executed");
      executed = true;
    }
    captureCallStackTrace();
    eventListener.callStart(this);
      //调用dispatcher()的enqueuef方法，不过在里面传入一次新的参数，AsyncCall类
    client.dispatcher().enqueue(new AsyncCall(responseCallback));
  }
```

​	进入 AsyncCall类

```java
final class AsyncCall extends NamedRunnable {
    private final Callback responseCallback;

    AsyncCall(Callback responseCallback) {
      super("OkHttp %s", redactedUrl());
      this.responseCallback = responseCallback;
    }

    String host() {
      return originalRequest.url().host();
    }

    Request request() {
      return originalRequest;
    }

    RealCall get() {
      return RealCall.this;
    }

    @Override protected void execute() {
      boolean signalledCallback = false;
      try {
         //执行耗时的IO操作
		//获取拦截器链
        Response response = getResponseWithInterceptorChain();
        if (retryAndFollowUpInterceptor.isCanceled()) {
          signalledCallback = true;
          //回调，注意这里回调是在线程池中，而不是向当前的主线程回调
          responseCallback.onFailure(RealCall.this, new IOException("Canceled"));
        } else {
          signalledCallback = true;
           //回调，同上
          responseCallback.onResponse(RealCall.this, response);
        }
      } catch (IOException e) {
        if (signalledCallback) {
          // Do not signal the callback twice!
          Platform.get().log(INFO, "Callback failure for " + toLoggableString(), e);
        } else {
          eventListener.callFailed(RealCall.this, e);
          //回调
          responseCallback.onFailure(RealCall.this, e);
        }
      } finally {
        client.dispatcher().finished(this);
      }
    }
  }
```

​	查看AsyncCall的父类NamedRunnable

```java
/**
 * Runnable implementation which always sets its thread name.
 */
//实现了Runnable接口
public abstract class NamedRunnable implements Runnable {
  protected final String name;

  public NamedRunnable(String format, Object... args) {
    this.name = Util.format(format, args);
  }

  @Override public final void run() {
    String oldName = Thread.currentThread().getName();
    Thread.currentThread().setName(name);
    try {
      //执行抽象方法，也就是 AsyncCall中的execute
      execute();
    } finally {
      Thread.currentThread().setName(oldName);
    }
  }

  protected abstract void execute();
}
```

​	回到RealCall的enqueue，进入到Dispatcher().enqueue中

```java
//Dispatcher()类
synchronized void enqueue(AsyncCall call) {
     //如果正在运行的异步请求的数量小于maxRequests并且与该请求相同的主机数量小于maxRequestsPerHost
  if (runningAsyncCalls.size() < maxRequests && runningCallsForHost(call) < maxRequestsPerHost) {
      //放入runningAsyncCalls队列中
    runningAsyncCalls.add(call);
      //这里调用了executorService()
    executorService().execute(call);
  } else {
      //否则，放入readyAsyncCalls队列
    readyAsyncCalls.add(call);
  }
}
```

​	当线程池执行AsyncCall任务时，它的execute方法会被调用

​	查看Dispatcher的finished方法

```java
//Dispatcher
/** Used by {@code AsyncCall#run} to signal completion. */
void finished(AsyncCall call) {
  //异步请求结束时调用此方法
  finished(runningAsyncCalls, call, true);
}

/** Used by {@code Call#execute} to signal completion. */
void finished(RealCall call) {
  //同步请求结束时调用此方法
  finished(runningSyncCalls, call, false);
}
/**
*将执行完毕的call从相应的队列移除
*/
private <T> void finished(Deque<T> calls, T call, boolean promoteCalls) {
    int runningCallsCount;
    Runnable idleCallback;
    synchronized (this) {
       //从相应的队列中移除相应的call，如果不包含，抛异常
      if (!calls.remove(call)) throw new AssertionError("Call wasn't in-flight!");
       //是否需要提升Call的级别
      if (promoteCalls) promoteCalls();
      runningCallsCount = runningCallsCount();
      idleCallback = this.idleCallback;
    }
		//如果没有任何需要执行的请求，那么执行idleCallBack	
    if (runningCallsCount == 0 && idleCallback != null) {
      idleCallback.run();
    }
  }
```

​	查看promoteCalls()

```java
  private void promoteCalls() {
  
    //运行中的异步任务队列大于等于最大的请求数
    if (runningAsyncCalls.size() >= maxRequests) return; // Already running max capacity.
    //待执行异步任务队列为空
    if (readyAsyncCalls.isEmpty()) return; // No ready calls to promote.

    //遍历等待队列
    for (Iterator<AsyncCall> i = readyAsyncCalls.iterator(); i.hasNext(); ) {
      AsyncCall call = i.next();

      //判断该请求的host是否小于每个host最大请求阈值
      if (runningCallsForHost(call) < maxRequestsPerHost) {
           //将该请求从readyAsyncCalls移除，加入runningAsyncCalls并执行
        i.remove();
        runningAsyncCalls.add(call);
        executorService().execute(call);
      }
	//如果runningAsyncCalls数量已经达到阈值，终止遍历
      if (runningAsyncCalls.size() >= maxRequests) return; // Reached max capacity.
    }
  }
```

​	总体流程图

![img](https://upload-images.jianshu.io/upload_images/5004304-28ab1ba9d0fba853.PNG?imageMogr2/auto-orient/strip|imageView2/2/w/884/format/webp)

## 3.OkHttp的拦截器和封装

​	在OKHttp中，中Interceptors拦截器是一种强大的机制，可以监视，重写和重试Call请求。

### 3.1OkHttp的拦截器的作用：

​	*拦截器可以一次性对所有请求的返回值进行修改
​	*拦截器可以一次性对请求的参数和返回的结果进行编码，比如统一设置为UTF-8.
​	*拦截器可以对所有的请求做统一的日志记录，不需要在每个请求开始或者结束的位置都添加一个日志操作。
​	*其他需要对请求和返回进行统一处理的需求…

### 3.2OkHttp拦截器的分类

​	OkHttp中的拦截器分2个：APP层面的拦截器（Application Interception）网络请求层面的拦截器(Network Interception)。

### 3.3两种的区别

Application：

​	*不需要担心是否影响OKHttp的请求策略和请求速度
​	*即使从缓存中取数据，也会执行Application拦截器
​	*允许重试，即Chain.proceed()可以执行多次。
​	*可以监听观察这个请求的最原始的未改变的意图(请求头，请求体等)，无法操作OKHttp为我们自动添加额外的请求头
​	*无法操作中间的响应结果，比如当URL重定向发生以及请求重试，只能操作客户端主动第一次请求以及最终的响应结果

Network Interceptors

​	*可以修改OkHttp框架自动添加的一些属性，即允许操作中间响应，比如当请求操作发生重定向或者重试等。
​	*可以观察最终完整的请求参数（也就是最终服务器接收到的请求数据和熟悉）

### 3.4实例化appInterceptor拦截器

```java

/**
 * 应用拦截器
 */
Interceptor appInterceptor = new Interceptor() {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();
            HttpUrl url = request.url();
            String s = url.url().toString();
		   //---------请求之前--------
            Log.d(TAG, "app intercept:begin ");
            Response response = chain.proceed(request);//请求
            Log.d(TAG, "app intercept:end");
            //---------请求之后------------
            return response;
        }
    };

```

### 3.5实例化networkInterceptor拦截器

```java
    /**
     * 网络拦截器
     */
    Interceptor networkInterceptor = new Interceptor() {
                @Override
                public Response intercept(Chain chain) throws IOException {
                    Request request = chain.request();
                    //---------请求之前-----
                    Log.d(TAG,"network interceptor:begin");
                    Response  response = chain.proceed(request);//请求
                    Log.d(TAG,"network interceptor:end");
                    return response;
                }
            };
```

### 3.6拦截器的实际应用

#### 3.6.1统一添加Header

​	应用场景:后台要求在请求API时，在每一个接口的请求头添加上对于的Token。这时候就可以使用拦截器对他们进行统一配置。

​	实例化拦截器

```java
  Interceptor  TokenHeaderInterceptor = new Interceptor() {
        @Override
        public Response intercept(Chain chain) throws IOException {
            // get token
            String token = AppService.getToken();
            Request originalRequest = chain.request();
            // get new request, add request header
            Request updateRequest = originalRequest.newBuilder()
                    .header("token", token)
                    .build();
            return chain.proceed(updateRequest);
        }
    };
```

#### 3.6.2改变请求体

​	应用场景:在上面的 login 接口基础上，后台要求我们传过去的请求参数是要按照一定规则经过加密的。

​	规则：

​	*请求参数名统一为content；

​	*content值：JSON 格式的字符串经过 AES 加密后的内容

​	实例化拦截器

```java
    Interceptor  RequestEncryptInterceptor = new Interceptor() {

        private static final String FORM_NAME = "content";
        private static final String CHARSET = "UTF-8";
        @Override
        public Response intercept(Chain chain) throws IOException {
            // get token
            Request request = chain.request();

            RequestBody body = request.body();

            if (body instanceof FormBody){
                FormBody formBody = (FormBody) body;
                Map<String, String> formMap = new HashMap<>();

                // 从 formBody 中拿到请求参数，放入 formMap 中
                for (int i = 0; i < formBody.size(); i++) {
                    formMap.put(formBody.name(i), formBody.value(i));
                }

                // 将 formMap 转化为 json 然后 AES 加密
                Gson gson = new Gson();
                String jsonParams = gson.toJson(formMap);
                String encryptParams = AESCryptUtils.encrypt(jsonParams.getBytes(CHARSET), AppConstant.getAESKey());

                // 重新修改 body 的内容
                body = new FormBody.Builder().add(FORM_NAME, encryptParams).build();
            }

            if (body != null) {
                request = request.newBuilder()
                        .post(body)
                        .build();
            }
            return chain.proceed(request);
        }
    };
```



## 4.拦截器链

### 4.1getResponseWithInterceptorChain方法

​	同步和异步响应中都出现了getResponseWithInterceptorChain方法

```java
//RealCall
Response getResponseWithInterceptorChain() throws IOException {
    // Build a full stack of interceptors.
    List<Interceptor> interceptors = new ArrayList<>();
    //添加应用拦截器
    interceptors.addAll(client.interceptors());
    //添加重试和重定向拦截器
    interceptors.add(retryAndFollowUpInterceptor);
    //添加转换拦截器
    interceptors.add(new BridgeInterceptor(client.cookieJar()));
    //添加缓存拦截器
    interceptors.add(new CacheInterceptor(client.internalCache()));
    //添加连接拦截器
    interceptors.add(new ConnectInterceptor(client));
     //添加网络拦截器
    if (!forWebSocket) {
      interceptors.addAll(client.networkInterceptors());
    }
    interceptors.add(new CallServerInterceptor(forWebSocket));
	//生成拦截器链
    Interceptor.Chain chain = new RealInterceptorChain(interceptors, null, null, null, 0,
        originalRequest, this, eventListener, client.connectTimeoutMillis(),
        client.readTimeoutMillis(), client.writeTimeoutMillis());

    return chain.proceed(originalRequest);
  }
```

​	从上面的代码可以看出，向interceptors添加了一系列的拦截器。最后构造了一个RealInterceptorChain对象，该类是拦截器链的具体体现，携带了整个拦截器链，包含了所有的应用拦截器，OKHttp的核心。

​	OKHttp这种拦截器链采用的是责任链模式，这样的好处就是讲请求的发送和处理分开处理，并且可以动态添加中间处理实现对请求的处理和短路操作。

### 4.2RealInterceptorChain类

```java
public final class RealInterceptorChain implements Interceptor.Chain {
  private final List<Interceptor> interceptors;//传递的拦截器集合
  private final StreamAllocation streamAllocation;
  private final HttpCodec httpCodec;
  private final RealConnection connection;
  private final int index; //当前拦截器的索引
  private final Request request;//当前的realReques
  private final Call call;
  private final EventListener eventListener;
  private final int connectTimeout;
  private final int readTimeout;
  private final int writeTimeout;
  private int calls;

  public RealInterceptorChain(List<Interceptor> interceptors, StreamAllocation streamAllocation,
      HttpCodec httpCodec, RealConnection connection, int index, Request request, Call call,
      EventListener eventListener, int connectTimeout, int readTimeout, int writeTimeout) {
    this.interceptors = interceptors; 
    this.connection = connection;
    this.streamAllocation = streamAllocation;
    this.httpCodec = httpCodec;
    this.index = index;
    this.request = request;
    this.call = call;
    this.eventListener = eventListener;
    this.connectTimeout = connectTimeout;
    this.readTimeout = readTimeout;
    this.writeTimeout = writeTimeout;
  }
   .....
}
```

​	在getResponseWithInterceptorChain()最后返回代码时调用了拦截器链的prooceed方法

​	

```java
//RealInterceptorChain
 public Response proceed(Request request, StreamAllocation streamAllocation, HttpCodec httpCodec,
      RealConnection connection) throws IOException {
    if (index >= interceptors.size()) throw new AssertionError();

    calls++;

    //错误处理相关
    // If we already have a stream, confirm that the incoming request will use it.
    if (this.httpCodec != null && !this.connection.supportsUrl(request.url())) {
      throw new IllegalStateException("network interceptor " + interceptors.get(index - 1)
          + " must retain the same host and port");
    }

    // If we already have a stream, confirm that this is the only call to chain.proceed().
    if (this.httpCodec != null && calls > 1) {
      throw new IllegalStateException("network interceptor " + interceptors.get(index - 1)
          + " must call proceed() exactly once");
    }

    // Call the next interceptor in the chain.
    //核心代码
    RealInterceptorChain next = new RealInterceptorChain(interceptors, streamAllocation, httpCodec,
        connection, index + 1, request, call, eventListener, connectTimeout, readTimeout,
        writeTimeout);
    //获取下一个拦截器
    Interceptor interceptor = interceptors.get(index);
    //调用当前拦截器的intercept方法，并将下一个拦截器传入其中。
    Response response = interceptor.intercept(next);

    // Confirm that the next interceptor made its required call to chain.proceed().
    if (httpCodec != null && index + 1 < interceptors.size() && next.calls != 1) {
      throw new IllegalStateException("network interceptor " + interceptor
          + " must call proceed() exactly once");
    }

    // Confirm that the intercepted response isn't null.
    if (response == null) {
      throw new NullPointerException("interceptor " + interceptor + " returned null");
    }

    if (response.body() == null) {
      throw new IllegalStateException(
          "interceptor " + interceptor + " returned a response with no body");
    }

    return response;
  }
```

#### 4.2.1RetryAndFollowUpInterceptor

​	按照添加的顺序逐个分析各个拦截器

​	RetryAndFollowUpInterceptor拦截器可以从错误中恢复和重定向，如果Call被取消了，那么将会抛出IoException。
​	查看其intercept方法

```java
 @Override public Response intercept(Chain chain) throws IOException {
    Request request = chain.request();
    RealInterceptorChain realChain = (RealInterceptorChain) chain;
    Call call = realChain.call();
    EventListener eventListener = realChain.eventListener();

    //①
    StreamAllocation streamAllocation = new StreamAllocation(client.connectionPool(),
        createAddress(request.url()), call, eventListener, callStackTrace);
    this.streamAllocation = streamAllocation;

    int followUpCount = 0;
    Response priorResponse = null;
    //②
    while (true) {
      if (canceled) {
        streamAllocation.release();
        throw new IOException("Canceled");
      }

      Response response;
      boolean releaseConnection = true;
      try {
        response = realChain.proceed(request, streamAllocation, null, null);
        releaseConnection = false;
      } catch (RouteException e) {
        // The attempt to connect via a route failed. The request will not have been sent.
        // 网络链接超时
        if (!recover(e.getLastConnectException(), streamAllocation, false, request)) {
          throw e.getLastConnectException();
        }
        releaseConnection = false;
        continue;
      } catch (IOException e) {
        // An attempt to communicate with a server failed. The request may have been sent.
        boolean requestSendStarted = !(e instanceof ConnectionShutdownException);
        if (!recover(e, streamAllocation, requestSendStarted, request)) throw e;
        releaseConnection = false;
        continue;
      } finally {
        // We're throwing an unchecked exception. Release any resources.
        if (releaseConnection) {
          streamAllocation.streamFailed(null);
          streamAllocation.release();
        }
      }

      // Attach the prior response if it exists. Such responses never have a body.
      if (priorResponse != null) {
        response = response.newBuilder()
            .priorResponse(priorResponse.newBuilder()
                    .body(null)
                    .build())
            .build();
      }

      Request followUp = followUpRequest(response, streamAllocation.route());

      if (followUp == null) {
        if (!forWebSocket) {
          streamAllocation.release();
        }
        return response;
      }

      closeQuietly(response.body());

      if (++followUpCount > MAX_FOLLOW_UPS) {
        streamAllocation.release();
        throw new ProtocolException("Too many follow-up requests: " + followUpCount);
      }

      if (followUp.body() instanceof UnrepeatableRequestBody) {
        streamAllocation.release();
        throw new HttpRetryException("Cannot retry streamed HTTP body", response.code());
      }

      if (!sameConnection(response, followUp.url())) {
        streamAllocation.release();
        streamAllocation = new StreamAllocation(client.connectionPool(),
            createAddress(followUp.url()), call, eventListener, callStackTrace);
        this.streamAllocation = streamAllocation;
      } else if (streamAllocation.codec() != null) {
        throw new IllegalStateException("Closing the body of " + response
            + " didn't close its backing stream. Bad interceptor?");
      }

      request = followUp;
      priorResponse = response;
    }
  }
```

##### 4.2.1.1StreamAllocation

​	源码①.创建了一个StreamAllocation，这个是用来做连接分配的，传递的参数有五个，第一个是前面创建的连接池，第二个是调用createAddress创建的Address，第三个是Call。

```java
//①
    StreamAllocation streamAllocation = new StreamAllocation(client.connectionPool(),
         createAddress(request.url()), call, eventListener, callStackTrace);
    this.streamAllocation = streamAllocation;
```

​	createAddress方法

```java
private Address createAddress(HttpUrl url) {
    SSLSocketFactory sslSocketFactory = null;
    HostnameVerifier hostnameVerifier = null;
    CertificatePinner certificatePinner = null;
    //如果是https
    if (url.isHttps()) {
      sslSocketFactory = client.sslSocketFactory();
      hostnameVerifier = client.hostnameVerifier();
      certificatePinner = client.certificatePinner();
    }

    return new Address(url.host(), url.port(), client.dns(), client.socketFactory(),
        sslSocketFactory, hostnameVerifier, certificatePinner, client.proxyAuthenticator(),
        client.proxy(), client.protocols(), client.connectionSpecs(), client.proxySelector());
  }
```

​	Address类的构造方法

```java
 //一个url构成的Address对象有：主机名host、端口号port、Dns、代理服务器proxy等元素
public Address(String uriHost, int uriPort, Dns dns, SocketFactory socketFactory,
      @Nullable SSLSocketFactory sslSocketFactory, @Nullable HostnameVerifier hostnameVerifier,
      @Nullable CertificatePinner certificatePinner, Authenticator proxyAuthenticator,
      @Nullable Proxy proxy, List<Protocol> protocols, List<ConnectionSpec> connectionSpecs,
      ProxySelector proxySelector) {
    this.url = new HttpUrl.Builder()
        .scheme(sslSocketFactory != null ? "https" : "http")
        .host(uriHost)
        .port(uriPort)
        .build();

    if (dns == null) throw new NullPointerException("dns == null");
    //Dns是一个接口，如果OkhttpClient在使用中没有配置自己的DNS实现则使用Okttp默认DNS.SYSTEM对象：
    this.dns = dns;
    /**
     Dns SYSTEM = new Dns() {
    @Override public List<InetAddress> lookup(String hostname) throws UnknownHostException {
      if (hostname == null) throw new UnknownHostException("hostname == null");
      try {
        return Arrays.asList(InetAddress.getAllByName(hostname));
      } catch (NullPointerException e) {
        UnknownHostException unknownHostException =
            new UnknownHostException("Broken system behaviour for dns lookup of " + hostname);
        unknownHostException.initCause(e);
        throw unknownHostException;
      }
    }
  };
	*/
    /**  
    调用了根据url中的主机名hostname通过getAllByName 获取InetAddress对象的集合。因为有些计算机会有多个Internet地址，getAllByName方法包含所有对应此主机名的地址，通常有多个ip地址的主机大多数都是有着非常高吞吐量的web服务器（服务器集群）。比如如果getAllByName（“www.baidu.com”）的话，打印List 集合中InetAddress对象的toString方法发现有多个如下格式的输出，格式为（hostname/ip地址）*：	
			[www.baidu.com/180.101.49.12, www.baidu.com/180.101.49.11]
			[www.baidu.com/180.101.49.12, www.baidu.com/180.101.49.11]
    */

    if (socketFactory == null) throw new NullPointerException("socketFactory == null");
    this.socketFactory = socketFactory;

    if (proxyAuthenticator == null) {
      throw new NullPointerException("proxyAuthenticator == null");
    }
    this.proxyAuthenticator = proxyAuthenticator;

    if (protocols == null) throw new NullPointerException("protocols == null");
    this.protocols = Util.immutableList(protocols);

    if (connectionSpecs == null) throw new NullPointerException("connectionSpecs == null");
    this.connectionSpecs = Util.immutableList(connectionSpecs);

    if (proxySelector == null) throw new NullPointerException("proxySelector == null");
    this.proxySelector = proxySelector;

    this.proxy = proxy;
    this.sslSocketFactory = sslSocketFactory;
    this.hostnameVerifier = hostnameVerifier;
    this.certificatePinner = certificatePinner;
  }
```

​	根据client和请求的信息初始化了Address

​	查看StreamAllocation

```java
  public StreamAllocation(ConnectionPool connectionPool, Address address, Call call,
      EventListener eventListener, Object callStackTrace) {
    this.connectionPool = connectionPool;
    this.address = address;
    this.call = call;
    this.eventListener = eventListener;
    //路由选择器
    this.routeSelector = new RouteSelector(address, routeDatabase(), call, eventListener);
    this.callStackTrace = callStackTrace;
  }
```

​	路由即是网络数据包在网络中的传输路径，或者说数据包在传输过程中所经过的网络节点，比如路由器，代理服务器之类的。

​	OkHttp3这样的网络库对于数据包的路由,用户可以为终端设置代理服务器，HTTP/HTTPS代理或SOCK代理。OkHttp3中的路由相关逻辑，需要从系统中获取用户设置的代理服务器的地址，将HTTP请求转换为代理协议的数据包，发给代理服务器，然后等待代理服务器帮助完成了网络请求之后，从代理服务器读取响应数据返回给用户。只有这样，用户设置的代理才能生效。如果网络库无视用户设置的代理服务器，直接进行DNS并做网络请求，则用户设置的代理服务器不生效。

​	如同Internet上的其它设备一样，每个路由节点都有自己的IP地址，加上端口号，则可以确定唯一的路由服务。以域名描述的HTTP/HTTPS代理服务器地址，可能对应于多个实际的代理服务器主机，因而一个代理服务器可能包含有多条路由。而SOCK代理服务器，则有着唯一确定的IP地址和端口号。

​	OkHttp3借助于RouteSelector来选择路由节点，并维护路由的信息。

​	RouteSelector对象的初始化需要Address和RouteDatabase这两个对象

​	RouteSelector构造器

```java
 public RouteSelector(Address address, RouteDatabase routeDatabase, Call call,
      EventListener eventListener) {
    this.address = address;
    //用于记录连接失败的路由的黑名单，如果在黑名单，不用尝试
    this.routeDatabase = routeDatabase;
    this.call = call;
    this.eventListener = eventListener;

    resetNextProxy(address.url(), address.proxy());
  }
```

​	除了简单的为属性赋值之外，还调用了resetNextProxy方法，该方法的主要作用就是初始化RouteSelector类中的代理服务器集合proxies：

```java
  /** Prepares the proxy servers to try. */
  private void resetNextProxy(HttpUrl url, Proxy proxy) {
    if (proxy != null) {//客户端配置了自己的代理
      // If the user specifies a proxy, try that and only that.
      proxies = Collections.singletonList(proxy);
    } else {
        //通过ProxySelector.getDefault();对象来获取默认代理
      // Try each of the ProxySelector choices until one connection succeeds.
      List<Proxy> proxiesOrNull = address.proxySelector().select(url.uri());
      proxies = proxiesOrNull != null && !proxiesOrNull.isEmpty()
          ? Util.immutableList(proxiesOrNull)
          : Util.immutableList(Proxy.NO_PROXY);
    }
      //访问proxies集合的下标，初始化为0
    nextProxyIndex = 0;
  }
```

​		客户端在配置OkttCilent对象的时候是可以通过Okhttp的Builder对象来创建自己的代理服务器，用户配置的代理服务器对象proxy会交给上文所说的Address对象，进而交给RouteSelector.当然用户如果没有配置代理服务器对象，则OhttpClinet使用ProxySelector.getDefault()这个ProxySelector对象的select方法返回默认的代理服务器集合，当然如果没有找到代理服务器，则使用Proxy.NO_PROXY，表示当前Address对网络的请求完全绕开代理服务器，直接连接远程主机

​	此时RouteSelector的初始化完成

​	RouteSelector的作用就是选择路由，在OKhttp中返回一个可用的Route对象。下面通过其next方法（）具体分析。

```java
public Selection next() throws IOException {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }

    // Compute the next set of routes to attempt.
    List<Route> routes = new ArrayList<>();
    while (hasNextProxy()) {//如果多余的代理服务器
      // Postponed routes are always tried last. For example, if we have 2 proxies and all the
      // routes for proxy1 should be postponed, we'll move to proxy2. Only after we've exhausted
      // all the good routes will we attempt the postponed routes.
      Proxy proxy = nextProxy();
      for (int i = 0, size = inetSocketAddresses.size(); i < size; i++) {
        Route route = new Route(address, proxy, inetSocketAddresses.get(i));
          //将address对象、lastProxy对象和InetSocketAddress组成一个Route对象并返回
        if (routeDatabase.shouldPostpone(route)) {
          postponedRoutes.add(route);
        } else {
          routes.add(route);
        }
      }

      if (!routes.isEmpty()) {
        break;
      }
    }

    if (routes.isEmpty()) {
      // We've exhausted all Proxies so fallback to the postponed routes.
      routes.addAll(postponedRoutes);
      postponedRoutes.clear();
    }

    return new Selection(routes);
  }
```

​	inetSocketAddresses集合的初始化在nextProxy（）方法里

```java
  /** Returns the next proxy to try. May be PROXY.NO_PROXY but never null. */
  private Proxy nextProxy() throws IOException {
    if (!hasNextProxy()) {
      throw new SocketException("No route to " + address.url().host()
          + "; exhausted proxy configurations: " + proxies);
    }
      //从 proxies获取一个代理服务器
    Proxy result = proxies.get(nextProxyIndex++);
      //重置inetSocketAddresses集合
    resetNextInetSocketAddress(result);
    return result;
  }
```

​	看看resetNextInetSocketAddress方法：

```java
 /** Prepares the socket addresses to attempt for the current proxy or host. */
  private void resetNextInetSocketAddress(Proxy proxy) throws IOException {
    // Clear the addresses. Necessary if getAllByName() below throws!
      //初始化InternetSocketAdds集合
    inetSocketAddresses = new ArrayList<>();
	//主机名
    String socketHost;
     //端口号
    int socketPort;
      //如果不使用代理或者使用SOCKS的代理服务器
    if (proxy.type() == Proxy.Type.DIRECT || proxy.type() == Proxy.Type.SOCKS) {
      socketHost = address.url().host();//获取目标服务器的主机
      socketPort = address.url().port();//获取目标服务器的端口号
    } else {//如果HTPP代理服务器
         //获取SocketAddress对象
      SocketAddress proxyAddress = proxy.address();
      if (!(proxyAddress instanceof InetSocketAddress)) {
        throw new IllegalArgumentException(
            "Proxy.address() is not an " + "InetSocketAddress: " + proxyAddress.getClass());
      }
         //转换成InetSocketAddress 对象
      InetSocketAddress proxySocketAddress = (InetSocketAddress) proxyAddress;
        //获取代理服务器的主机名和端口号
      socketHost = getHostString(proxySocketAddress);
      socketPort = proxySocketAddress.getPort();
    }

    if (socketPort < 1 || socketPort > 65535) {
      throw new SocketException("No route to " + socketHost + ":" + socketPort
          + "; port is out of range");
    }

      //如果是socks代理，直接放入集合
    if (proxy.type() == Proxy.Type.SOCKS) {
      inetSocketAddresses.add(InetSocketAddress.createUnresolved(socketHost, socketPort));
    } else {//如果是http代理或者是无代理连接
        
      eventListener.dnsStart(call, socketHost);

      // Try each address for best behavior in mixed IPv4/IPv6 environments.
         //获取ip地址列表
      List<InetAddress> addresses = address.dns().lookup(socketHost);
        //先DNS解析，得到InetAddress列表（没有端口）
      if (addresses.isEmpty()) {
        throw new UnknownHostException(address.dns() + " returned no addresses for " + socketHost);
      }

      eventListener.dnsEnd(call, socketHost, addresses);
		 //根据ip列表地址创建多个InetSocketAddress
      for (int i = 0, size = addresses.size(); i < size; i++) {
        InetAddress inetAddress = addresses.get(i);
        inetSocketAddresses.add(new InetSocketAddress(inetAddress, socketPort));//（带上端口）
      }
    }
  }
```

​	resetNextInetSocketAddress方法作用：

​	1、根据proxies选中的Proxy代理服务器来创建nextInetSocketAddress集合。（也就是说如果有下一个代理的话，上一个代理服务器的InteSocketAddress数据会设置空，因为nextInetSocketAddress集合重新初始化了)
​	2、根据Proxy的类型来获取服务器主机的主机名和端口号，如果没有使用代理或者是使用了SOCKS代理服务器，则根据url直接获取主机名和端口号。如果使用了HTTP的代理，则获取代理服务器的地址（SocketAddress），然后通过InetSocketAddress 获取代理服务器的主机名和端口号。
​	3、得到主机名socketHost 和端口号socketPort 之后如果是SOCKETS代理服务器，则通过这两个信息创建一个InetSocketAddress对象添加到集合里。如果使用的是Http代理服务器或者没有使用代理服务器，则通过上文所说的DNS根据得到的主机名socketHost 获取ip地址列表（List<InetAddress>集合）来为每一个ip组成的InetAddress对象，构建一个InetSocketAddress，并添加到inetSocketAddresses中。

​	RouteSelector主要做了这样一些事情：

1. 在RouteSelector对象创建时，获取并保存用户设置的所有的代理。这里主要通过`ProxySelector`，根据uri来得到系统中的所有代理，并保存在Proxy列表proxies中。
2. 给调用者提供接口，来选择可用的路由。调用者通过next()可以获取`RouteSelector`中维护的下一个可用路由。调用者在连接失败时，可以再次调用这个接口来获取下一个路由。这个接口会逐个地返回每个代理的每个代理主机服务给调用者。在所有的代理的每个代理主机都被访问过了之后，还会返回曾经连接失败的路由。
3. 维护路由节点的信息。RouteDatabase用于维护连接失败的路由的信息，以避免浪费时间去连接一些不可用的路由。`RouteDatabase`中的路由信息主要由RouteSelector来维护。



​	OkHttp3主要用(Address, Proxy, InetSocketAddress)的三元组来描述路由信息：

```java
public final class Route {
  final Address address;
  final Proxy proxy;
  final InetSocketAddress inetSocketAddress;

  public Route(Address address, Proxy proxy, InetSocketAddress inetSocketAddress) {
    if (address == null) {
      throw new NullPointerException("address == null");
    }
    if (proxy == null) {
      throw new NullPointerException("proxy == null");
    }
    if (inetSocketAddress == null) {
      throw new NullPointerException("inetSocketAddress == null");
    }
    this.address = address;
    this.proxy = proxy;
    this.inetSocketAddress = inetSocketAddress;
  }
```

​	在创建OkHttpClient时，可以通过为OkHttpClient.Builder设置`ProxySelector`来定制`ProxySelector`。若没有指定，则所有的为默认`ProxySelector`。OpenJDK 1.8版默认的`ProxySelector`为`sun.net.spi.DefaultProxySelector`：



##### 4.2.1.2发生请求&接收响应

​	回到intercept，看源码②while处代码,先看上半部分

```java
while (true) {
      if (canceled) { //查看请求是否取消
        streamAllocation.release();
        throw new IOException("Canceled");
      }

      Response response;//响应
      boolean releaseConnection = true;//是否需要重连
      try {
        //调用拦截器链的proceed方法，在这个方法中，会调用下一个拦截器
        //这就是拦截器链的顺序调用
        response = realChain.proceed(request, streamAllocation, null, null);
        releaseConnection = false;
      } catch (RouteException e) {
        // The attempt to connect via a route failed. The request will not have been sent.
        if (!recover(e.getLastConnectException(), streamAllocation, false, request)) {
          throw e.getLastConnectException();
        }
        releaseConnection = false;
        continue;
      } catch (IOException e) {
        // An attempt to communicate with a server failed. The request may have been sent.
        boolean requestSendStarted = !(e instanceof ConnectionShutdownException);
        if (!recover(e, streamAllocation, requestSendStarted, request)) throw e;
        releaseConnection = false;
        continue;
      } finally {
        // We're throwing an unchecked exception. Release any resources.
	  //释放资源
        if (releaseConnection) {
  
          streamAllocation.streamFailed(null);
          streamAllocation.release();
        }
      }
    
     .......
    }
```

​	查看recover方法

```java
 private boolean recover(IOException e, StreamAllocation streamAllocation,
      boolean requestSendStarted, Request userRequest) {
    streamAllocation.streamFailed(e);

    // The application layer has forbidden retries.
    //应用层禁止重试
    if (!client.retryOnConnectionFailure()) return false;

    // We can't send the request body again.
    //不能再发送请求体了
    if (requestSendStarted && userRequest.body() instanceof UnrepeatableRequestBody) return false;

    // This exception is fatal.
    //这个异常无法重试
    if (!isRecoverable(e, requestSendStarted)) return false;

    // No more routes to attempt.
    //没有更多的attempt
    if (!streamAllocation.hasMoreRoutes()) return false;

    // For failure recovery, use the same route selector with a new connection.
    //上面的条件都不满足，此时就可以进行重试
    return true;
  }
```

##### 	4.2.1.3错误重试和重定向

​	来看while循环的下半部分

```java
while(true){
......
  // Attach the prior response if it exists. Such responses never have a body.
  //priorResponse不为空，说明之前已经获得响应
      if (priorResponse != null) {
      //结合当前的response和之前的response获得新的response。
        response = response.newBuilder()
            .priorResponse(priorResponse.newBuilder()
                    .body(null)
                    .build())
            .build();
      }
 
     //调用followUpRequest查看响应是否需要重定向，如果不需要重定向则返回当前请求,如果需要返回新的请求
     // followUpRequest源码见下
      Request followUp = followUpRequest(response, streamAllocation.route());

      //不需要重定向或者无法重定向
      if (followUp == null) {
        if (!forWebSocket) {
          streamAllocation.release();
        }
        return response;
      }

      closeQuietly(response.body());

     //重试次数+1
     //重试次数超过MAX_FOLLOW_UPS（默认20），抛出异常
      if (++followUpCount > MAX_FOLLOW_UPS) {
        streamAllocation.release();
        throw new ProtocolException("Too many follow-up requests: " + followUpCount);
      }

      //followUp与当前的响应对比，是否为同一个连接
      if (followUp.body() instanceof UnrepeatableRequestBody) {
        streamAllocation.release();
        throw new HttpRetryException("Cannot retry streamed HTTP body", response.code());
      }

     //followUp与当前请求的不是同一个连接时，则重写申请重新设置streamAllocation
      if (!sameConnection(response, followUp.url())) {
        streamAllocation.release();
        streamAllocation = new StreamAllocation(client.connectionPool(),
            createAddress(followUp.url()), call, eventListener, callStackTrace);
        this.streamAllocation = streamAllocation;
      } else if (streamAllocation.codec() != null) {
        throw new IllegalStateException("Closing the body of " + response
            + " didn't close its backing stream. Bad interceptor?");
      }
   
      //重新设置reques，并把当前的Response保存到priorResponse，继续while循环
      request = followUp;
      priorResponse = response;
    }
```

​	followUpRequest的源码

```java
  private Request followUpRequest(Response userResponse, Route route) throws IOException {
    if (userResponse == null) throw new IllegalStateException();
    //返回的响应码
    int responseCode = userResponse.code();
    
    //请求方法
    final String method = userResponse.request().method();
    switch (responseCode) {
     //407请求要求代理的身份认证
      case HTTP_PROXY_AUTH:
        Proxy selectedProxy = route != null
            ? route.proxy()
            : client.proxy();
        if (selectedProxy.type() != Proxy.Type.HTTP) {
          throw new ProtocolException("Received HTTP_PROXY_AUTH (407) code while not using proxy");
        }
        return client.proxyAuthenticator().authenticate(route, userResponse);

      //401请求要求用户的身份认证
      case HTTP_UNAUTHORIZED:
        return client.authenticator().authenticate(route, userResponse);

      //307&308 临时重定向。使用GET请求重定向
      case HTTP_PERM_REDIRECT:
      case HTTP_TEMP_REDIRECT:
        // "If the 307 or 308 status code is received in response to a request other than GET
        // or HEAD, the user agent MUST NOT automatically redirect the request"
        if (!method.equals("GET") && !method.equals("HEAD")) {
          return null;
        }
        // fall-through
        
      case HTTP_MULT_CHOICE: //300多种选择。请求的资源可包括多个位置，相应可返回一个资源特征与地址的列表用于用户终端（例如：浏览器）选择
      case HTTP_MOVED_PERM://301永久移动。请求的资源已被永久的移动到新URI，返回信息会包括新的URI，浏览器会自动定向到新URI。
      case HTTP_MOVED_TEMP://302临时移动。与301类似。但资源只是临时被移动。
      case HTTP_SEE_OTHER://303查看其它地址。与301类似。使用GET和POST请求查看
        // Does the client allow redirects?
        if (!client.followRedirects()) return null;

        String location = userResponse.header("Location");
        if (location == null) return null;
        HttpUrl url = userResponse.request().url().resolve(location);

        // Don't follow redirects to unsupported protocols.
        if (url == null) return null;

        // If configured, don't follow redirects between SSL and non-SSL.
        boolean sameScheme = url.scheme().equals(userResponse.request().url().scheme());
        if (!sameScheme && !client.followSslRedirects()) return null;

        // Most redirects don't include a request body.
        Request.Builder requestBuilder = userResponse.request().newBuilder();
        if (HttpMethod.permitsRequestBody(method)) {
          final boolean maintainBody = HttpMethod.redirectsWithBody(method);
          if (HttpMethod.redirectsToGet(method)) {
            requestBuilder.method("GET", null);
          } else {
            RequestBody requestBody = maintainBody ? userResponse.request().body() : null;
            requestBuilder.method(method, requestBody);
          }
          if (!maintainBody) {
            
            requestBuilder.removeHeader("Transfer-Encoding");
            requestBuilder.removeHeader("Content-Length");
            requestBuilder.removeHeader("Content-Type");
          }
        }

        // When redirecting across hosts, drop all authentication headers. This
        // is potentially annoying to the application layer since they have no
        // way to retain them.
        if (!sameConnection(userResponse, url)) { 
        //移出请求头
          requestBuilder.removeHeader("Authorization");
        }

        return requestBuilder.url(url).build();

      case HTTP_CLIENT_TIMEOUT: //408 服务器无法根据客户端请求的内容特性完成请求
        // 408's are rare in practice, but some servers like HAProxy use this response code. The
        // spec says that we may repeat the request without modifications. Modern browsers also
        // repeat the request (even non-idempotent ones.)
        if (!client.retryOnConnectionFailure()) {
          // The application layer has directed us not to retry the request.
          return null;
        }

        if (userResponse.request().body() instanceof UnrepeatableRequestBody) {
          return null;
        }

        if (userResponse.priorResponse() != null
            && userResponse.priorResponse().code() == HTTP_CLIENT_TIMEOUT) {
          // We attempted to retry and got another timeout. Give up.
          return null;
        }

        if (retryAfter(userResponse, 0) > 0) {
          return null;
        }

        return userResponse.request();

      case HTTP_UNAVAILABLE://503 	由于超载或系统维护，服务器暂时的无法处理客户端的请求。延时的长度可包含在服务器的Retry-After头信息中
        if (userResponse.priorResponse() != null
            && userResponse.priorResponse().code() == HTTP_UNAVAILABLE) {
          // We attempted to retry and got another timeout. Give up.
          return null;
        }

        if (retryAfter(userResponse, Integer.MAX_VALUE) == 0) {
          // specifically received an instruction to retry without delay
          return userResponse.request();
        }

        return null;

      default:
        return null;
    }
  }
```

### 4.3BridgeInterceptor类

​	在RetryAndFollowUpInterceptor 执行response = realChain.proceed(request, streamAllocation, null, null)代码时，此时会调用下一个拦截器，即BridgeInterceptor拦截器

​	BridgeInterceptor转换拦截器主要工作就是为请求添加请求头，为响应添加响应头

#### 	4.3.1intercept

​	BridgeInterceptor的intercept代码

​	下面代码主要为request添加Content-Type(文档类型)、Content-Length(内容长度)或Transfer-Encoding，从这里我们也可以发现其实这些头信息是不需要我们手动添加的.即使我们手动添加也会被覆盖掉。

​	

```java
    if (body != null) {
      MediaType contentType = body.contentType();
      if (contentType != null) {
        requestBuilder.header("Content-Type", contentType.toString());
      }

      long contentLength = body.contentLength();
      if (contentLength != -1) {
        requestBuilder.header("Content-Length", Long.toString(contentLength));
        requestBuilder.removeHeader("Transfer-Encoding");
      } else {
        requestBuilder.header("Transfer-Encoding", "chunked");
        requestBuilder.removeHeader("Content-Length");
      }
    }
```

​	下面的代码时为Host、Connection和User-Agent字段添加默认值，不过不同于上面的，这几个属性只有用户没有设置时，OkHttp会自动添加，如果你收到添加时，不会被覆盖掉。

```java
  if (userRequest.header("Host") == null) {
      requestBuilder.header("Host", hostHeader(userRequest.url(), false));
    }

    if (userRequest.header("Connection") == null) {
      requestBuilder.header("Connection", "Keep-Alive");
    }

    if (userRequest.header("User-Agent") == null) {
      requestBuilder.header("User-Agent", Version.userAgent());
    }
```

​	默认支持gzip压缩

```java
    // If we add an "Accept-Encoding: gzip" header field we're responsible for also decompressing
    // the transfer stream.
    boolean transparentGzip = false;
    if (userRequest.header("Accept-Encoding") == null && userRequest.header("Range") == null) {
      transparentGzip = true;
      requestBuilder.header("Accept-Encoding", "gzip");
    }
```

​	cookie部分

```java
   List<Cookie> cookies = cookieJar.loadForRequest(userRequest.url());
    if (!cookies.isEmpty()) {
      requestBuilder.header("Cookie", cookieHeader(cookies));
    }
```

​	进入cookHeader方法

```java
/** Returns a 'Cookie' HTTP request header with all cookies, like {@code a=b; c=d}. */
  private String cookieHeader(List<Cookie> cookies) {
    StringBuilder cookieHeader = new StringBuilder();
    for (int i = 0, size = cookies.size(); i < size; i++) {
      if (i > 0) {
        cookieHeader.append("; ");
      }
      Cookie cookie = cookies.get(i);
      cookieHeader.append(cookie.name()).append('=').append(cookie.value());
    }
    return cookieHeader.toString();
  }
```

​	之后就是进入下一个拦截器中，并将最后的响应返回

```java
  Response networkResponse = chain.proceed(requestBuilder.build());
```

​	在获得响应后，如果有cookie，则保存

```java
HttpHeaders.receiveHeaders(cookieJar, userRequest.url(), networkResponse.headers());
```

​	

```java
 public static void receiveHeaders(CookieJar cookieJar, HttpUrl url, Headers headers) {
    if (cookieJar == CookieJar.NO_COOKIES) return;

    List<Cookie> cookies = Cookie.parseAll(url, headers);
    if (cookies.isEmpty()) return;

    cookieJar.saveFromResponse(url, cookies);
  }
```

​	下面就是对response的解压工作，将流转换为直接能使用的response，然后对header进行了一些处理构建了一个response返回给上一个拦截器。

```java
 if (transparentGzip
        && "gzip".equalsIgnoreCase(networkResponse.header("Content-Encoding"))
        && HttpHeaders.hasBody(networkResponse)) {
      GzipSource responseBody = new GzipSource(networkResponse.body().source());
      Headers strippedHeaders = networkResponse.headers().newBuilder()
          .removeAll("Content-Encoding")
          .removeAll("Content-Length")
          .build();
      responseBuilder.headers(strippedHeaders);
      String contentType = networkResponse.header("Content-Type");
      responseBuilder.body(new RealResponseBody(contentType, -1L, Okio.buffer(responseBody)));
    }

    return responseBuilder.build();
```

#### 	4.3.2总结

​	从上面的代码可以看出了，先获取原请求头，然后在请求中添加请求头，然后在根据需求，决定是否要填充Cookie，在对原始请求做出处理后，使用chain的procced方法得到响应，接下来对响应做处理得到用户响应，最后返回响应

### 4.4CacheInterceptor类

#### 4.4.1传入参数

​	CacheInterceptor创建时传入的参数

```java
interceptors.add(new CacheInterceptor(client.internalCache()));
```

​	查看client的internalCache方法，可以看出。CacheInterceptor使用OkHttpClient的internalCache方法的返回值作为参数

```java
  InternalCache internalCache() {
    return cache != null ? cache.internalCache : internalCache;
  }
```

```java
   /** Sets the response cache to be used to read and write cached responses. */
    void setInternalCache(@Nullable InternalCache internalCache) {
      this.internalCache = internalCache;
      this.cache = null;
    }

    /** Sets the response cache to be used to read and write cached responses. */
    public Builder cache(@Nullable Cache cache) {
      this.cache = cache;
      this.internalCache = null;
      return this;
    }
```

​	（1）OkHttpClient中有2个跟缓存有关的变量，一个是Cache，一个是internalCache。其中我们可以通过Builder来设置Cache，但是不能设置internalCache。

​	（2）从上面可以看出，默认Cache和internalCache都是null，也就是OkHttpClient没有默认的缓存实现。

​	（3）缓存拦截器CacheInterceptor中的internalCache来自OkHttpClient的Cache，因为OkHttpClient中的internalCache一直是null，我们没法从外界设置，所以如果我们没有为OkHttpClient设置Cache，那么缓存拦截器中的internalCache就也为null了，也就没法提供缓存功能。

#### 4.4.2缓存策略

​	接下来进入CacheInterceptor的intercept方法中
​	下面这段代码是获得缓存响应 和获得响应策略

```java
//CacheInterceptor.intercept（）中
 //如果我们没有设置缓存或是当前request没有缓存，那么cacheCandidate就为null了
Response cacheCandidate = cache != null
        ? cache.get(chain.request())
        : null;

    long now = System.currentTimeMillis();
	//如果我们没有设置缓存，或是当前request没有缓存，那么cacheCandidate就为null
    //获取具体的缓存策略	
    CacheStrategy strategy = new CacheStrategy.Factory(now, chain.request(), cacheCandidate).get();
    Request networkRequest = strategy.networkRequest; //网络请求，如果为null就代表不用进行网络请求
    Response cacheResponse = strategy.cacheResponse;//缓存响应，如果为null，则代表不使用缓存
```

​	进入查看CacheStrategy中的Factory类

```java
//CacheStrategy.Factory类
//构造方法
 public Factory(long nowMillis, Request request, Response cacheResponse) {
      this.nowMillis = nowMillis;
      this.request = request;
      this.cacheResponse = cacheResponse;

      if (cacheResponse != null) {
        this.sentRequestMillis = cacheResponse.sentRequestAtMillis();
        this.receivedResponseMillis = cacheResponse.receivedResponseAtMillis();
        Headers headers = cacheResponse.headers();

        //获取响应头的各种信息
        for (int i = 0, size = headers.size(); i < size; i++) {
          String fieldName = headers.name(i);
          String value = headers.value(i);
          if ("Date".equalsIgnoreCase(fieldName)) {
            servedDate = HttpDate.parse(value);
            servedDateString = value;
          } else if ("Expires".equalsIgnoreCase(fieldName)) {
            expires = HttpDate.parse(value);
          } else if ("Last-Modified".equalsIgnoreCase(fieldName)) {
            lastModified = HttpDate.parse(value);
            lastModifiedString = value;
          } else if ("ETag".equalsIgnoreCase(fieldName)) {
            etag = value;
          } else if ("Age".equalsIgnoreCase(fieldName)) {
            ageSeconds = HttpHeaders.parseSeconds(value, -1);
          }
        }
      }
    }
```

​	继续查看Factory的get方法

```java
//CacheStrategy.Factory类
    public CacheStrategy get() {
      CacheStrategy candidate = getCandidate();

      //如果设置取消缓存
      if (candidate.networkRequest != null && request.cacheControl().onlyIfCached()) {
        // We're forbidden from using the network and the cache is insufficient.
        return new CacheStrategy(null, null);
      }

      return candidate;
    }
```

​	继续查看getCandidate()方法,可以看出，在这个方法里，就是最终决定缓存策略的方法

```java
//CacheStrategy.Factory类
private CacheStrategy getCandidate() {
      // No cached response.
      //如果没有response的缓存，那就使用请求。
      if (cacheResponse == null) {
        return new CacheStrategy(request, null);
      }

      // Drop the cached response if it's missing a required handshake.
      //如果请求是https的并且缺少必要的握手信息，那么重新请求。
      if (request.isHttps() && cacheResponse.handshake() == null) {
        return new CacheStrategy(request, null);
      }

      // If this response shouldn't have been stored, it should never be used
      // as a response source. This check should be redundant as long as the
      // persistence store is well-behaved and the rules are constant.
      ////根据request和response是否能被缓存来生成CacheStrategy
      if (!isCacheable(cacheResponse, request)) {
        return new CacheStrategy(request, null);
      }
       
      //如果请求指定不使用缓存响应，或者是可选择的，就重新请求。
      CacheControl requestCaching = request.cacheControl();
    	//如果Request中的noCache标志位为true或是request的请求头中包含"If-Modified-Since"或是"If-None-Match"标志位
      if (requestCaching.noCache() || hasConditions(request)) {
        return new CacheStrategy(request, null);
      }

    	 //如果缓存的response中的immutable标志位为true，则不请求网络
      CacheControl responseCaching = cacheResponse.cacheControl();
      if (responseCaching.immutable()) {
        return new CacheStrategy(null, cacheResponse);
      }

      long ageMillis = cacheResponseAge();
      long freshMillis = computeFreshnessLifetime();

      if (requestCaching.maxAgeSeconds() != -1) {
        freshMillis = Math.min(freshMillis, SECONDS.toMillis(requestCaching.maxAgeSeconds()));
      }

      long minFreshMillis = 0;
      if (requestCaching.minFreshSeconds() != -1) {
        minFreshMillis = SECONDS.toMillis(requestCaching.minFreshSeconds());
      }

      long maxStaleMillis = 0;
      if (!responseCaching.mustRevalidate() && requestCaching.maxStaleSeconds() != -1) {
        maxStaleMillis = SECONDS.toMillis(requestCaching.maxStaleSeconds());
      }

       //如果response有缓存，并且时间比较近，添加一些头部信息后，返回request = null的策略
       /（意味着虽过期，但可用，只是会在响应头添加warning）
      if (!responseCaching.noCache() && ageMillis + minFreshMillis < freshMillis + maxStaleMillis) {
        Response.Builder builder = cacheResponse.newBuilder();
        if (ageMillis + minFreshMillis >= freshMillis) {
          builder.addHeader("Warning", "110 HttpURLConnection \"Response is stale\"");
        }
        long oneDayMillis = 24 * 60 * 60 * 1000L;
        if (ageMillis > oneDayMillis && isFreshnessLifetimeHeuristic()) {
          builder.addHeader("Warning", "113 HttpURLConnection \"Heuristic expiration\"");
        }
        return new CacheStrategy(null, builder.build());
      }

      // Find a condition to add to the request. If the condition is satisfied, the response body
      // will not be transmitted.
      String conditionName;
      //流程走到这，说明缓存已经过期了
      //Etag是属于HTTP 1.1属性，它是由服务器生成返回给前端，当第一次发起HTTP请求时，服务器会返回一个Etag，
      //并在你第二次发起同一个请求时，客户端会同时发送一个If-None-Match，而它的值就是Etag的值（此处由发起请求的客户端来设置）。
      //然后，服务器会比对这个客服端发送过来的Etag是否与服务器的相同，如果相同，就将If-None-Match的值设为false，返回状态为304，客户端继续使用本地缓存，不解析服务器返回的数据（这种场景服务器也不返回数据，因为服务器的数据没有变化嘛）
    // 如果不相同，就将If-None-Match的值设为true，返回状态为200，客户端重新解析服务器返回的数据	
	//ETag 实体标签: 一般为资源实体的哈希值  即ETag就是服务器生成的一个标记，用来标识返回值是否有变化。且Etag的优先级高于Last-Modified。
    
    /**
     Last-Modified & If-Modified-Since

	Last-Modified与Etag类似。不过Last-Modified表示响应资源在服务器最后修改时间而已。与Etag相比，不足为：

　　（1）、Last-Modified标注的最后修改只能精确到秒级，如果某些文件在1秒钟以内，被修改多次的话，它将不能准确标注文件的修改时间；

　　（2）、如果某些文件会被定期生成，当有时内容并没有任何变化，但Last-Modified却改变了，导致文件没法使用缓存；

　　（3）、有可能存在服务器没有准确获取文件修改时间，或者与代理服务器时间不一致等情形。

	然而，Etag是服务器自动生成或者由开发者生成的对应资源在服务器端的唯一标识符，能够更加准确的控制缓存。
    */

      if (etag != null) {
        conditionName = "If-None-Match";
        conditionValue = etag;
      } else if (lastModified != null) {
        conditionName = "If-Modified-Since";
        conditionValue = lastModifiedString;
      } else if (servedDate != null) {
        conditionName = "If-Modified-Since";
        conditionValue = servedDateString;
      } else {
        return new CacheStrategy(request, null); // No condition! Make a regular request.
      }

      Headers.Builder conditionalRequestHeaders = request.headers().newBuilder();
      Internal.instance.addLenient(conditionalRequestHeaders, conditionName, conditionValue);

      Request conditionalRequest = request.newBuilder()
          .headers(conditionalRequestHeaders.build())
          .build();
      return new CacheStrategy(conditionalRequest, cacheResponse);
    }
```

​	CacheStrategy的构造方法

```java
 CacheStrategy(Request networkRequest, Response cacheResponse) {
    this.networkRequest = networkRequest;
    this.cacheResponse = cacheResponse;
  }
```

#### 4.4.3执行策略

​	intercept中执行策略的部分

```java
//intercept中
     //根据缓存策略，更新统计指标：请求次数、使用网络请求次数、使用缓存次数
    if (cache != null) {
      cache.trackResponse(strategy);
    }
 
    //缓存不可用，关闭
    if (cacheCandidate != null && cacheResponse == null) {
      closeQuietly(cacheCandidate.body()); // The cache candidate wasn't applicable. Close it.
    }

    //如果既无网络请求可用，又无缓存，返回504错误
    // If we're forbidden from using the network and the cache is insufficient, fail.
    if (networkRequest == null && cacheResponse == null) {
      return new Response.Builder()
          .request(chain.request())
          .protocol(Protocol.HTTP_1_1)
          .code(504)
          .message("Unsatisfiable Request (only-if-cached)")
          .body(Util.EMPTY_RESPONSE)
          .sentRequestAtMillis(-1L)
          .receivedResponseAtMillis(System.currentTimeMillis())
          .build();
    }

    // If we don't need the network, we're done.
    //缓存可用，直接返回缓存
    if (networkRequest == null) {
      return cacheResponse.newBuilder()
          .cacheResponse(stripBody(cacheResponse))
          .build();
    }
```

#### 4.4.4进行网络请求

​	intercept中进行网络请求的部分

```java
//intercept中
 Response networkResponse = null;
    try {
      //进行网络请求-->调用下一个拦截器
      networkResponse = chain.proceed(networkRequest);
    } finally {
      // If we're crashing on I/O or otherwise, don't leak the cache body.
      if (networkResponse == null && cacheCandidate != null) {
        closeQuietly(cacheCandidate.body());
      }
    }

    // If we have a cache response too, then we're doing a conditional get.
    if (cacheResponse != null) {

      //响应码为304，缓存有效，合并网络请求和缓存
      //304 请求资源未修改
      if (networkResponse.code() == HTTP_NOT_MODIFIED) {
        Response response = cacheResponse.newBuilder()
            .headers(combine(cacheResponse.headers(), networkResponse.headers()))
            .sentRequestAtMillis(networkResponse.sentRequestAtMillis())
            .receivedResponseAtMillis(networkResponse.receivedResponseAtMillis())
            .cacheResponse(stripBody(cacheResponse))
            .networkResponse(stripBody(networkResponse))
            .build();
        networkResponse.body().close();

        // Update the cache after combining headers but before stripping the
        // Content-Encoding header (as performed by initContentStream()).
        //在合并头部之后更新缓存，但是在剥离内容编码头之前（由initContentStream（）执行）。
        cache.trackConditionalCacheHit();
        cache.update(cacheResponse, response);
        return response;
      } else {
        closeQuietly(cacheResponse.body());
      }
    }

    Response response = networkResponse.newBuilder()
        .cacheResponse(stripBody(cacheResponse))
        .networkResponse(stripBody(networkResponse))
        .build();

    if (cache != null) {
      //如果有响应体并且可缓存，那么将响应写入缓存。
      if (HttpHeaders.hasBody(response) && CacheStrategy.isCacheable(response, networkRequest)) {
        // Offer this request to the cache.
        CacheRequest cacheRequest = cache.put(response);
        return cacheWritingResponse(cacheRequest, response);
      }

      //如果request无效
      if (HttpMethod.invalidatesCache(networkRequest.method())) {
        try {
        //从缓存删除
          cache.remove(networkRequest);
        } catch (IOException ignored) {
          // The cache cannot be written.
        }
      }
    }

    return response;
```

### 4.5ConnectInterceptor类

​	ConnectInterceptor,是一个连接相关的拦截器,作用就是打开与服务器之间的连接，正式开启OkHttp的网络请求

​	首先还是先看ConnectInterceptor类的intercept方法

#### 4.5.1 intercept

```java
 @Override public Response intercept(Chain chain) throws IOException {
    RealInterceptorChain realChain = (RealInterceptorChain) chain;
    Request request = realChain.request();
    //首先从realChain拿到了streamAllocation对象，这个对象在RetryAndFollowInterceptor中就已经初始化过了
    //只不过一直没有使用，到了ConnectTnterceptor才使用。
    StreamAllocation streamAllocation = realChain.streamAllocation();

    // We need the network to satisfy this request. Possibly for validating a conditional GET.
    //判断是否为GET请求
    boolean doExtensiveHealthChecks = !request.method().equals("GET");
    //生成一个HttpCodec对象。这个对象是用于编码request和解码response的一个封装好的对象。
    HttpCodec httpCodec = streamAllocation.newStream(client, chain, doExtensiveHealthChecks);
    RealConnection connection = streamAllocation.connection();

    //将创建好的HttpCode和connection对象传递给下一个拦截器
    return realChain.proceed(request, streamAllocation, httpCodec, connection);
  }
```

​		用来创建HttpCodec的newStream()方法：

```java
public final class StreamAllocation {

......

  public HttpCodec newStream(OkHttpClient client, boolean doExtensiveHealthChecks) {
    int connectTimeout = client.connectTimeoutMillis();
    int readTimeout = client.readTimeoutMillis();
    int writeTimeout = client.writeTimeoutMillis();
    boolean connectionRetryEnabled = client.retryOnConnectionFailure();

    try {
        //建立连接
      RealConnection resultConnection = findHealthyConnection(connectTimeout, readTimeout,
          writeTimeout, connectionRetryEnabled, doExtensiveHealthChecks);

        /**
        用前面创建的连接来创建HttpCodec。 对于HTTP/1.1创建Http1Codec，对于HTTP/2则创建Http2Codec。HttpCodec用于处理与HTTP具体协议相关的部分。比如HTTP/1.1是基于文本的协议，而HTTP/2则是基于二进制格式的协议，HttpCodec用于将请求编码为对应协议要求的传输格式，并在得到响应时，对数据进行解码。
        */
      HttpCodec resultCodec;
      if (resultConnection.http2Connection != null) {
        resultCodec = new Http2Codec(client, this, resultConnection.http2Connection);
      } else {
        resultConnection.socket().setSoTimeout(readTimeout);
        resultConnection.source.timeout().timeout(readTimeout, MILLISECONDS);
        resultConnection.sink.timeout().timeout(writeTimeout, MILLISECONDS);
        resultCodec = new Http1Codec(
            client, this, resultConnection.source, resultConnection.sink);
      }

      synchronized (connectionPool) {
        codec = resultCodec;
        return resultCodec;
      }
    } catch (IOException e) {
      throw new RouteException(e);
    }
  }
```

`findHealthyConnection()`中创建连接的过程：

```java
/**
   * Finds a connection and returns it if it is healthy. If it is unhealthy the process is repeated
   * until a healthy connection is found.
   */
  private RealConnection findHealthyConnection(int connectTimeout, int readTimeout,
      int writeTimeout, boolean connectionRetryEnabled, boolean doExtensiveHealthChecks)
      throws IOException {
    while (true) {
      RealConnection candidate = findConnection(connectTimeout, readTimeout, writeTimeout,
          connectionRetryEnabled);

      // If this is a brand new connection, we can skip the extensive health checks.
      synchronized (connectionPool) {
        if (candidate.successCount == 0) {
          return candidate;
        }
      }

      // Do a (potentially slow) check to confirm that the pooled connection is still good. If it
      // isn't, take it out of the pool and start again.
      if (!candidate.isHealthy(doExtensiveHealthChecks)) {
        noNewStreams();
        continue;
      }

      return candidate;
    }
  }
```

​	在这个方法中，是找到一个连接，然后判断其是否可用。如果可用则将找到的连接返回给调用者，否则寻找下一个连接。寻找连接可能是建立一个新的连接，也可能是复用连接池中的一个连接。

​	来看寻找连接的过程`findConnection()`：

```java
**
   * Returns a connection to host a new stream. This prefers the existing connection if it exists,
   * then the pool, finally building a new connection.
   */
  private RealConnection findConnection(int connectTimeout, int readTimeout, int writeTimeout,
      boolean connectionRetryEnabled) throws IOException {
    Route selectedRoute;
    synchronized (connectionPool) {
        /**
        检查上次分配的连接是否可用，若可用则，则将上次分配的连接返回给调用者。
        */
      if (released) throw new IllegalStateException("released");
      if (codec != null) throw new IllegalStateException("codec != null");
      if (canceled) throw new IOException("Canceled");

      RealConnection allocatedConnection = this.connection;
      if (allocatedConnection != null && !allocatedConnection.noNewStreams) {
        return allocatedConnection;
      }

      // Attempt to get a connection from the pool.
        /**
        上次分配的连接不存在，或不可用，则从连接池中查找一个连接，查找的依据就是Address，也就是连接的对端地址，以及路由等信息。			Internal.instance指向OkHttpClient的一个内部类的对象，Internal.instance.get()实际会通过ConnectionPool的				get(Address address, StreamAllocation streamAllocation)`方法来尝试获取RealConnection。 若能从连接池中找到所需			要的连接，则将连接返回给调用者。	
        */
      RealConnection pooledConnection = Internal.instance.get(connectionPool, address, this);
      if (pooledConnection != null) {
        this.connection = pooledConnection;
        return pooledConnection;
      }
		/**
		从连接池中没有找到所需要的连接，则会首先选择路由。
		*/
      selectedRoute = route;
    }
	
    if (selectedRoute == null) {
      selectedRoute = routeSelector.next();
      synchronized (connectionPool) {
        route = selectedRoute;
        refusedStreamCount = 0;
      }
    }
       /**
       创建新的连接RealConnection对象。
       */
    RealConnection newConnection = new RealConnection(selectedRoute);

    synchronized (connectionPool) {
      /**
      acquire新创建的连接RealConnection对象，并将它放进连接池。
      */
        acquire(newConnection);
        
      Internal.instance.put(connectionPool, newConnection);
      this.connection = newConnection;
      if (canceled) throw new IOException("Canceled");
    }
	/**
	调用newConnection.connect()建立连接。
	*/
    newConnection.connect(connectTimeout, readTimeout, writeTimeout, address.connectionSpecs(),
        connectionRetryEnabled);
    routeDatabase().connected(newConnection.route());

    return newConnection;
  }
```

​	在ConnectionPool的get()操作执行的过程：

```java
private final Deque<RealConnection> connections = new ArrayDeque<>();
  final RouteDatabase routeDatabase = new RouteDatabase();
  boolean cleanupRunning;

  /** Returns a recycled connection to {@code address}, or null if no such connection exists. */
  RealConnection get(Address address, StreamAllocation streamAllocation) {
    assert (Thread.holdsLock(this));
    for (RealConnection connection : connections) {
      if (connection.allocations.size() < connection.allocationLimit
          && address.equals(connection.route().address)
          && !connection.noNewStreams) {
        streamAllocation.acquire(connection);
        return connection;
      }
    }
    return null;
  }
```

​	ConnectionPool连接池是连接的容器，这里用了一个Deque来保存所有的连接RealConnection。而get的过程就是，遍历保存的所有连接来匹配address。同时connection.allocations.size()要满足connection.allocationLimit的限制。 在找到了所需要的连接之后，会acquire该连接。
​	acquire连接的过程

```java
public final class StreamAllocation {

......

  /**
   * Use this allocation to hold {@code connection}. Each call to this must be paired with a call to
   * {@link #release} on the same connection.
   */
  public void acquire(RealConnection connection) {
    assert (Thread.holdsLock(connectionPool));
    connection.allocations.add(new StreamAllocationReference(this, callStackTrace));
  }
```

​	给RealConnection的allocations添加一个到该StreamAllocation的引用。这样看来，同一个连接RealConnection似乎同时可以为多个HTTP请求服务。多个HTTP/1.1请求是不能在同一个连接上交叉处理的。这里似乎有问题

看connection.allocationLimit的更新设置。RealConnection中如下的两个地方会设置这个值：

```java
public final class RealConnection extends Http2Connection.Listener implements Connection {

......

  private void establishProtocol(int readTimeout, int writeTimeout,
      ConnectionSpecSelector connectionSpecSelector) throws IOException {
    if (route.address().sslSocketFactory() != null) {
      connectTls(readTimeout, writeTimeout, connectionSpecSelector);
    } else {
      protocol = Protocol.HTTP_1_1;
      socket = rawSocket;
    }

    if (protocol == Protocol.HTTP_2) {
      socket.setSoTimeout(0); // Framed connection timeouts are set per-stream.

      Http2Connection http2Connection = new Http2Connection.Builder(true)
          .socket(socket, route.address().url().host(), source, sink)
          .listener(this)
          .build();
      http2Connection.start();

      // Only assign the framed connection once the preface has been sent successfully.
      this.allocationLimit = http2Connection.maxConcurrentStreams();
      this.http2Connection = http2Connection;
    } else {
      this.allocationLimit = 1;
    }
  }
  
  /** When settings are received, adjust the allocation limit. */
  @Override public void onSettings(Http2Connection connection) {
    allocationLimit = connection.maxConcurrentStreams();
  }
```

​	可以看到，若不是HTTP/2的连接，则allocationLimit的值总是1。由此可见，StreamAllocation以及RealConnection的allocations/allocationLimit这样的设计，主要是为了实现HTTP/2 多路复用的特性。否则的话，大概为RealConnection用一个inUse标记就可以了。 那回到StreamAllocation的`findConnection()`，来看新创建的RealConnection对象建立连接的过程，即RealConnection的connect()：

```java
ublic final class RealConnection extends Http2Connection.Listener implements Connection {
  private final Route route;

  /** The low-level TCP socket. */
  private Socket rawSocket;

  /**
   * The application layer socket. Either an {@link SSLSocket} layered over {@link #rawSocket}, or
   * {@link #rawSocket} itself if this connection does not use SSL.
   */
  public Socket socket;
  private Handshake handshake;
  private Protocol protocol;
  public volatile Http2Connection http2Connection;
  public int successCount;
  public BufferedSource source;
  public BufferedSink sink;
  public int allocationLimit;
  public final List<Reference<StreamAllocation>> allocations = new ArrayList<>();
  public boolean noNewStreams;
  public long idleAtNanos = Long.MAX_VALUE;

  public RealConnection(Route route) {
    this.route = route;
  }

  public void connect(int connectTimeout, int readTimeout, int writeTimeout,
      List<ConnectionSpec> connectionSpecs, boolean connectionRetryEnabled) {
    if (protocol != null) throw new IllegalStateException("already connected");

    RouteException routeException = null;
    ConnectionSpecSelector connectionSpecSelector = new ConnectionSpecSelector(connectionSpecs);

    if (route.address().sslSocketFactory() == null) {
      if (!connectionSpecs.contains(ConnectionSpec.CLEARTEXT)) {
        throw new RouteException(new UnknownServiceException(
            "CLEARTEXT communication not enabled for client"));
      }
      String host = route.address().url().host();
      if (!Platform.get().isCleartextTrafficPermitted(host)) {
        throw new RouteException(new UnknownServiceException(
            "CLEARTEXT communication to " + host + " not permitted by network security policy"));
      }
    }

    while (protocol == null) {
      try {
        if (route.requiresTunnel()) {
          buildTunneledConnection(connectTimeout, readTimeout, writeTimeout,
              connectionSpecSelector);
        } else {
          buildConnection(connectTimeout, readTimeout, writeTimeout, connectionSpecSelector);
        }
      } catch (IOException e) {
        closeQuietly(socket);
        closeQuietly(rawSocket);
        socket = null;
        rawSocket = null;
        source = null;
        sink = null;
        handshake = null;
        protocol = null;

        if (routeException == null) {
          routeException = new RouteException(e);
        } else {
          routeException.addConnectException(e);
        }

        if (!connectionRetryEnabled || !connectionSpecSelector.connectionFailed(e)) {
          throw routeException;
        }
      }
    }
  }
```

​	根据路由的类型，来执行不同的创建连接的过程。对于需要创建隧道连接的路由，执行buildTunneledConnection()，而对于普通连接，则执行buildConnection()。

​	如何判断是否要建立隧道连接呢？来看

```java
/**
   * Returns true if this route tunnels HTTPS through an HTTP proxy. See <a
   * href="http://www.ietf.org/rfc/rfc2817.txt">RFC 2817, Section 5.2</a>.
   */
  public boolean requiresTunnel() {
    return address.sslSocketFactory != null && proxy.type() == Proxy.Type.HTTP;
  }
```

​	可以看到，通过代理服务器，来做https请求的连接(http/1.1的https和http2)需要建立隧道连接，而其它的连接则不需要建立隧道连接。

​	用于建立隧道连接的buildTunneledConnection()的过程：

```java
/**
   * Does all the work to build an HTTPS connection over a proxy tunnel. The catch here is that a
   * proxy server can issue an auth challenge and then close the connection.
   */
  private void buildTunneledConnection(int connectTimeout, int readTimeout, int writeTimeout,
      ConnectionSpecSelector connectionSpecSelector) throws IOException {
    Request tunnelRequest = createTunnelRequest();
    HttpUrl url = tunnelRequest.url();
    int attemptedConnections = 0;
    int maxAttempts = 21;
    while (true) {
      if (++attemptedConnections > maxAttempts) {
        throw new ProtocolException("Too many tunnel connections attempted: " + maxAttempts);
      }

      connectSocket(connectTimeout, readTimeout);
        /**
        建立隧道连接
        */
      tunnelRequest = createTunnel(readTimeout, writeTimeout, tunnelRequest, url);

      if (tunnelRequest == null) break; // Tunnel successfully created.

      // The proxy decided to close the connection after an auth challenge. We need to create a new
      // connection, but this time with the auth credentials.
      closeQuietly(rawSocket);
      rawSocket = null;
      sink = null;
      source = null;
    }
	/**
	建立Protocol
	*/
    establishProtocol(readTimeout, writeTimeout, connectionSpecSelector);
  }
```

建立隧道连接的过程，又分为了几个过程：

- 创建隧道请求
- 建立Socket连接
- 发送请求建立隧道

隧道请求是一个常规的HTTP请求，只是请求的内容有点特殊。初始的隧道请求如：

```java
/**
   * Returns a request that creates a TLS tunnel via an HTTP proxy. Everything in the tunnel request
   * is sent unencrypted to the proxy server, so tunnels include only the minimum set of headers.
   * This avoids sending potentially sensitive data like HTTP cookies to the proxy unencrypted.
   */
  private Request createTunnelRequest() {
    return new Request.Builder()
        .url(route.address().url())
        .header("Host", Util.hostHeader(route.address().url(), true))
        .header("Proxy-Connection", "Keep-Alive")
        .header("User-Agent", Version.userAgent()) // For HTTP/1.0 proxies like Squid.
        .build();
  }
```

建立socket连接的过程如下：

```java
private void connectSocket(int connectTimeout, int readTimeout) throws IOException {
    Proxy proxy = route.proxy();
    Address address = route.address();

    rawSocket = proxy.type() == Proxy.Type.DIRECT || proxy.type() == Proxy.Type.HTTP
        ? address.socketFactory().createSocket()
        : new Socket(proxy);

    rawSocket.setSoTimeout(readTimeout);
    try {
      Platform.get().connectSocket(rawSocket, route.socketAddress(), connectTimeout);
    } catch (ConnectException e) {
      throw new ConnectException("Failed to connect to " + route.socketAddress());
    }
    source = Okio.buffer(Okio.source(rawSocket));
    sink = Okio.buffer(Okio.sink(rawSocket));
  }
```

​	主要是创建一个到代理服务器或HTTP服务器的Socket连接。socketFactory最终来自于OkHttpClient，对于OpenJDK 8而言，默认为DefaultSocketFactory：

```java
/**
     * Returns a copy of the environment's default socket factory.
     *
     * @return the default <code>SocketFactory</code>
     */
    public static SocketFactory getDefault()
    {
        synchronized (SocketFactory.class) {
            if (theFactory == null) {
                //
                // Different implementations of this method SHOULD
                // work rather differently.  For example, driving
                // this from a system property, or using a different
                // implementation than JavaSoft's.
                //
                theFactory = new DefaultSocketFactory();
            }
        }

        return theFactory;
    }
```

创建隧道的过程是这样子的：

```java
/**
   * To make an HTTPS connection over an HTTP proxy, send an unencrypted CONNECT request to create
   * the proxy connection. This may need to be retried if the proxy requires authorization.
   */
  private Request createTunnel(int readTimeout, int writeTimeout, Request tunnelRequest,
      HttpUrl url) throws IOException {
    // Make an SSL Tunnel on the first message pair of each SSL + proxy connection.
    String requestLine = "CONNECT " + Util.hostHeader(url, true) + " HTTP/1.1";
    while (true) {
      Http1Codec tunnelConnection = new Http1Codec(null, null, source, sink);
      source.timeout().timeout(readTimeout, MILLISECONDS);
      sink.timeout().timeout(writeTimeout, MILLISECONDS);
      tunnelConnection.writeRequest(tunnelRequest.headers(), requestLine);
      tunnelConnection.finishRequest();
      Response response = tunnelConnection.readResponse().request(tunnelRequest).build();
      // The response body from a CONNECT should be empty, but if it is not then we should consume
      // it before proceeding.
      long contentLength = HttpHeaders.contentLength(response);
      if (contentLength == -1L) {
        contentLength = 0L;
      }
      Source body = tunnelConnection.newFixedLengthSource(contentLength);
      Util.skipAll(body, Integer.MAX_VALUE, TimeUnit.MILLISECONDS);
      body.close();

      switch (response.code()) {
        case HTTP_OK:
          // Assume the server won't send a TLS ServerHello until we send a TLS ClientHello. If
          // that happens, then we will have buffered bytes that are needed by the SSLSocket!
          // This check is imperfect: it doesn't tell us whether a handshake will succeed, just
          // that it will almost certainly fail because the proxy has sent unexpected data.
          if (!source.buffer().exhausted() || !sink.buffer().exhausted()) {
            throw new IOException("TLS tunnel buffered too many bytes!");
          }
          return null;

        case HTTP_PROXY_AUTH:
          tunnelRequest = route.address().proxyAuthenticator().authenticate(route, response);
          if (tunnelRequest == null) throw new IOException("Failed to authenticate with proxy");

          if ("close".equalsIgnoreCase(response.header("Connection"))) {
            return tunnelRequest;
          }
          break;

        default:
          throw new IOException(
              "Unexpected response code for CONNECT: " + response.code());
      }
    }
  }
```

​	主要HTTP 的 CONNECT 方法建立隧道。

​	而建立常规的连接的过程则为：

```java
/** Does all the work necessary to build a full HTTP or HTTPS connection on a raw socket. */
  private void buildConnection(int connectTimeout, int readTimeout, int writeTimeout,
      ConnectionSpecSelector connectionSpecSelector) throws IOException {
    connectSocket(connectTimeout, readTimeout);
    establishProtocol(readTimeout, writeTimeout, connectionSpecSelector);
  }
```

​	建立socket连接，然后建立Protocol。建立Protocol的过程为：

```java
private void establishProtocol(int readTimeout, int writeTimeout,
      ConnectionSpecSelector connectionSpecSelector) throws IOException {
    if (route.address().sslSocketFactory() != null) {
      connectTls(readTimeout, writeTimeout, connectionSpecSelector);
    } else {
      protocol = Protocol.HTTP_1_1;
      socket = rawSocket;
    }

    if (protocol == Protocol.HTTP_2) {
      socket.setSoTimeout(0); // Framed connection timeouts are set per-stream.

      Http2Connection http2Connection = new Http2Connection.Builder(true)
          .socket(socket, route.address().url().host(), source, sink)
          .listener(this)
          .build();
      http2Connection.start();

      // Only assign the framed connection once the preface has been sent successfully.
      this.allocationLimit = http2Connection.maxConcurrentStreams();
      this.http2Connection = http2Connection;
    } else {
      this.allocationLimit = 1;
    }
  }
```

HTTP/2协议的协商过程在connectTls()的过程中完成。

总结一下OkHttp3的连接RealConnection的含义，或者说是ConnectInterceptor从StreamAllocation中获取的RealConnection对象的状态：

1. 对于不使用HTTP代理的HTTP请求，为一个到HTTP服务器的Socket连接。后续直接向该Socket连接中写入常规的HTTP请求，并从中读取常规的HTTP响应。
2. 对于不使用代理的https请求，为一个到https服务器的Socket连接，但经过了TLS握手，协议协商等过程。后续直接向该Socket连接中写入常规的请求，并从中读取常规的响应。
3. 对于使用HTTP代理的HTTP请求，为一个到HTTP代理服务器的Socket连接。后续直接向该Socket连接中写入常规的HTTP请求，并从中读取常规的HTTP响应。
4. 对于使用代理的https请求，为一个到代理服务器的隧道连接，但经过了TLS握手，协议协商等过程。后续直接向该Socket连接中写入常规的请求，并从中读取常规的响应。

### 4.6CallServerInterceptor类

​	CallServerInterceptor是拦截器链中最后一个拦截器，负责将网络请求提交给服务器。

#### 	4.6.1intercept

​	准备工作，首先是获得各种对象，然后将请求写入 httpCodec中

```java
@Override public Response intercept(Chain chain) throws IOException {
    RealInterceptorChain realChain = (RealInterceptorChain) chain;
    HttpCodec httpCodec = realChain.httpStream();

  
    StreamAllocation streamAllocation = realChain.streamAllocation();
    //上一步已经完成连接工作的连接
    RealConnection connection = (RealConnection) realChain.connection();
    Request request = realChain.request();

    long sentRequestMillis = System.currentTimeMillis();

    realChain.eventListener().requestHeadersStart(realChain.call());
    //将请求头写入
    httpCodec.writeRequestHeaders(request);
    realChain.eventListener().requestHeadersEnd(realChain.call(), request)；
```

​	再将请求头写入后，会有一个关于Expect:100-continue的请求头处理。

```java
/**
	http 100-continue用于客户端在发送POST数据给服务器前，征询服务器情况，看服务器是否处理POST的数据，如果不处理，客户端则不上传POST数据，如果处理，则POST上传数据。在现实应用中，通过在POST大数据时，才会使用100-continue协议。如果服务器端可以处理，则会返回100，负责会返回错误码
	有这个字段，相当于一次简单的握手操作，会等待拿到服务器返回的ResponseHeaders之后再继续，如果服务器接收RequestBody，会返回null。
*/	
if ("100-continue".equalsIgnoreCase(request.header("Expect"))) { //如果有Expect:100-continue的请求头
        httpCodec.flushRequest();
        realChain.eventListener().responseHeadersStart(realChain.call());
        responseBuilder = httpCodec.readResponseHeaders(true); //读取响应头
      }
```

​	当返回的结果为null，或者不存在Expect:100-continue的请求头，则执行下面的代码，

```java
@Override public Response intercept(Chain chain) throws IOException {
    RealInterceptorChain realChain = (RealInterceptorChain) chain;
    HttpCodec httpCodec = realChain.httpStream();

  
    StreamAllocation streamAllocation = realChain.streamAllocation();
    //上一步已经完成连接工作的连接
    RealConnection connection = (RealConnection) realChain.connection();
    Request request = realChain.request();

    long sentRequestMillis = System.currentTimeMillis();

    realChain.eventListener().requestHeadersStart(realChain.call());
    //将请求头写入
    httpCodec.writeRequestHeaders(request);
    realChain.eventListener().requestHeadersEnd(realChain.call(), request)；
```

​	如果没有经历上面的Expect:100-continue的请求头，则重新请求一次。

```java
httpCodec.finishRequest();
	// 读取头部信息、状态码等
    if (responseBuilder == null) {
      realChain.eventListener().responseHeadersStart(realChain.call());
      responseBuilder = httpCodec.readResponseHeaders(false);
    }
```

​	将请求的结果(可能是Expect:100-continue请求的结果，也可能是正常的情况下)包装成response。

```java
 Response response = responseBuilder
        .request(request)
        .handshake(streamAllocation.connection().handshake())
        .sentRequestAtMillis(sentRequestMillis)
        .receivedResponseAtMillis(System.currentTimeMillis())
        .build();
```

​	如果请求的返回码为100(继续。客户端应继续其请求)

```java
int code = response.code();
    if (code == 100) {
      // server sent a 100-continue even though we did not request one.
      // try again to read the actual response
      responseBuilder = httpCodec.readResponseHeaders(false); //重新请求一次

      response = responseBuilder //覆盖之前的响应
              .request(request)
              .handshake(streamAllocation.connection().handshake())
              .sentRequestAtMillis(sentRequestMillis)
              .receivedResponseAtMillis(System.currentTimeMillis())
              .build();

      code = response.code();
    }
```

​	判断是否是是websocket并且响应码为101(切换协议)

```java
if (forWebSocket && code == 101) {
      // Connection is upgrading, but we need to ensure interceptors see a non-null response body.
     // 设置一个空的Body
      response = response.newBuilder()
          .body(Util.EMPTY_RESPONSE)//赋空值
          .build();
    } else {
     // 读取Body信息
      response = response.newBuilder()
          .body(httpCodec.openResponseBody(response)) //填充response的body
          .build();
    }
```

​	从请求头和响应头判断其中是否有表明需要保持连接打开

```java
  // 如果设置了连接关闭，则断开连接
if ("close".equalsIgnoreCase(response.request().header("Connection"))  
        || "close".equalsIgnoreCase(response.header("Connection"))) {
      streamAllocation.noNewStreams();
    }
```

​	处理204(无内容)和205(重置内容)

```java
 	//HTTP 204(no content) 代表响应报文中包含若干首部和一个状态行，但是没有实体的主体内容。
    //HTTP 205(reset content) 表示响应执行成功，重置页面（Form表单），方便用户下次输入
    //这里做了同样的处理，就是抛出协议异常。
if ((code == 204 || code == 205) && response.body().contentLength() > 0) {
      throw new ProtocolException(
          "HTTP " + code + " had non-zero Content-Length: " + response.body().contentLength());
    }
```

​	最后将response返回给上一个拦截器
