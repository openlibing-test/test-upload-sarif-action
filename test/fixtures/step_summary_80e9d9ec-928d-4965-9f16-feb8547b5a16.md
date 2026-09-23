````
# 华为云 CodeArts Check 代码扫描报告

## 1 任务摘要

| 任务名称 | 分支名称 | 门禁结果 |
| --- | --- | --- |
| openlibing-cicd-test-20260901163323 | test-thq-1 | 不通过 |

## 2 扫描结果概述

### 2.1 问题概览

| 问题级别 | 数量 | 门禁 | 结果 |
| --- | --- | --- | --- |
| 致命 | 0 | 0 | 通过 |
| 严重 | 0 | 0 | 通过 |
| [一般](#level-2-1) | 5 | 0 | 不通过 |
| [提示](#level-3-4) | 8 | 0 | 不通过 |

### 2.2 十大问题

| 编号 | 规则名称 | 问题数量 | 严重程度 |
| --- | --- | --- | --- |
| 1 | G.LOG.01 记录日志应该使用Facade模式的日志框架 | 3 | 一般 |
| 2 | G.FMT.12 减少不必要的空行，保持代码紧凑 | 2 | 提示 |
| 3 | G.CTL.01 不要在控制性条件表达式中执行赋值操作或执行复杂的条件判断 | 1 | 一般 |
| 4 | G.ERR.02 不要直接捕获异常的基类Throwable、Exception、RuntimeException | 1 | 一般 |
| 5 | G.CMT.05 文件头注释应该包含版权许可信息 | 1 | 提示 |
| 6 | G.NAM.08 布尔型变量建议以表达是非意义的动词开头 | 1 | 提示 |
| 7 | G.CMT.01 public或protected修饰的元素应添加Javadoc注释 | 1 | 提示 |
| 8 | G.CMT.02 顶层public类的Javadoc应该包含功能说明和创建日期/版本信息 | 1 | 提示 |
| 9 | G.FMT.02 一个源文件按顺序包含版权、package、import、顶层类，且用空行分隔 | 1 | 提示 |
| 10 | G.FMT.05 在条件语句和循环块中应该使用大括号 | 1 | 提示 |

### 2.3 问题级别

- 致命：需要立即修复的安全漏洞或严重错误
- 严重：可能导致系统不稳定或安全风险的问题
- 一般：代码规范或潜在的性能问题
- 提示：代码风格或最佳实践建议

### 2.4 扫描结果详情

#### 致命问题（0个）


#### 严重问题（0个）


#### 一般问题（5个）

- G.LOG.01 记录日志应该使用Facade模式的日志框架 (3)
- G.CTL.01 不要在控制性条件表达式中执行赋值操作或执行复杂的条件判断 (1)
- G.ERR.02 不要直接捕获异常的基类Throwable、Exception、RuntimeException (1)

#### 提示问题（8个）

- G.FMT.12 减少不必要的空行，保持代码紧凑 (2)
- G.CMT.05 文件头注释应该包含版权许可信息 (1)
- G.NAM.08 布尔型变量建议以表达是非意义的动词开头 (1)
- G.CMT.01 public或protected修饰的元素应添加Javadoc注释 (1)
- G.CMT.02 顶层public类的Javadoc应该包含功能说明和创建日期/版本信息 (1)
- G.FMT.02 一个源文件按顺序包含版权、package、import、顶层类，且用空行分隔 (1)
- G.FMT.05 在条件语句和循环块中应该使用大括号 (1)

### 2.5 详细问题列表

| 严重程度 | 规则名称 | 问题描述 | 代码文件 | 代码行 |
| 一般 | G.CTL.01 不要在控制性条件表达式中执行赋值操作或执行复杂的条件判断 | Do not compare expression with 'true' | java/test_java1.java | 28 |
| 一般 | G.ERR.02 不要直接捕获异常的基类Throwable、Exception、RuntimeException | Do not catch 'Exception' or 'RuntimeException' | java/test_java1.java | 24 |
| 一般 | G.LOG.01 记录日志应该使用Facade模式的日志框架 | Do not use System.out or System.err to log messages | java/test_java1.java | 6 |
| 一般 | G.LOG.01 记录日志应该使用Facade模式的日志框架 | Do not use System.out or System.err to log messages | java/test_java1.java | 18 |
| 一般 | G.LOG.01 记录日志应该使用Facade模式的日志框架 | Do not use System.out or System.err to log messages | java/test_java1.java | 29 |
| 提示 | G.CMT.05 文件头注释应该包含版权许可信息 | Missing file header comment at first line or file header comment not under the kia mark. | java/test_java1.java | 1 |
| 提示 | G.NAM.08 布尔型变量建议以表达是非意义的动词开头 | Boolean 'flag' should start with 'is', 'has', 'can' or 'should' | java/test_java1.java | 27 |
| 提示 | G.CMT.01 public或protected修饰的元素应添加Javadoc注释 | Missing javadoc on 'HelloWorld' which is public or protected | java/test_java1.java | 3 |
| 提示 | G.CMT.02 顶层public类的Javadoc应该包含功能说明和创建日期/版本信息 | Missing javadoc description | java/test_java1.java | 2 |
| 提示 | G.FMT.02 一个源文件按顺序包含版权、package、import、顶层类，且用空行分隔 | Do not use '*' in import declaration | java/test_java1.java | 1 |
| 提示 | G.FMT.05 在条件语句和循环块中应该使用大括号 | Conditional statements and loop blocks must use braces. | java/test_java1.java | 18 |
| 提示 | G.FMT.12 减少不必要的空行，保持代码紧凑 | Reduce unnecessary blank lines to keep code compact. | java/test_java1.java | 4 |
| 提示 | G.FMT.12 减少不必要的空行，保持代码紧凑 | Reduce unnecessary blank lines to keep code compact. | java/test_java1.java | 33 |

## 3 问题详细分析

### 3.1 一般 G.LOG.01 记录日志应该使用Facade模式的日志框架 (3)
<a id="level-2-1"></a>

**规则名称**: G.LOG.01 记录日志应该使用Facade模式的日志框架
**问题数量**: 3

**问题描述**:
Do not use System.out or System.err to log messages

**问题1.1**: java/test_java1.java:6,18,29

**问题代码**:
**问题代码1**: java/test_java1.java:6
```JAVA
import java.util.*;

public class HelloWorld {

    public static void main(String[] args) {
        System.out.println("Start");   // 1. 使用System.out（很多规则会告警）

        List list = new ArrayList();   // 2. 使用原始类型 raw type
        list.add("test");

        int a = 1;
```

**问题代码2**: java/test_java1.java:18
```JAVA
        int c = 3;
        int d = 4;
        int e = 5;                     // 3. 多个未使用变量

        if (a == 1)
            System.out.println("no brace");  // 4. if 没有使用大括号

        String password = "123456";   // 5. 硬编码敏感信息

        try {
            int x = 10 / 0;           // 6. 明显异常
```

**问题代码3**: java/test_java1.java:29
```JAVA
        } catch (Exception ex) {      // 7. 捕获过于宽泛
        }                             // 8. 空的 catch 块

        Boolean flag = true;
        if (flag == true) {           // 9. Boolean 比较写法不规范
            System.out.println("flag true");
        }

        long time = System.currentTimeMillis(); // 10. 未使用变量

    }
```

### 3.2 一般 G.CTL.01 不要在控制性条件表达式中执行赋值操作或执行复杂的条件判断 (1)
<a id="level-2-1"></a>

**规则名称**: G.CTL.01 不要在控制性条件表达式中执行赋值操作或执行复杂的条件判断
**问题数量**: 1

**问题描述**:
Do not compare expression with 'true'

**问题2.1**: java/test_java1.java:28

**问题代码**:
**问题代码1**: java/test_java1.java:28
```JAVA
            int x = 10 / 0;           // 6. 明显异常
        } catch (Exception ex) {      // 7. 捕获过于宽泛
        }                             // 8. 空的 catch 块

        Boolean flag = true;
        if (flag == true) {           // 9. Boolean 比较写法不规范
            System.out.println("flag true");
        }

        long time = System.currentTimeMillis(); // 10. 未使用变量

```

### 3.3 一般 G.ERR.02 不要直接捕获异常的基类Throwable、Exception、RuntimeException (1)
<a id="level-2-1"></a>

**规则名称**: G.ERR.02 不要直接捕获异常的基类Throwable、Exception、RuntimeException
**问题数量**: 1

**问题描述**:
Do not catch 'Exception' or 'RuntimeException'

**问题3.1**: java/test_java1.java:24

**问题代码**:
**问题代码1**: java/test_java1.java:24
```JAVA

        String password = "123456";   // 5. 硬编码敏感信息

        try {
            int x = 10 / 0;           // 6. 明显异常
        } catch (Exception ex) {      // 7. 捕获过于宽泛
        }                             // 8. 空的 catch 块

        Boolean flag = true;
        if (flag == true) {           // 9. Boolean 比较写法不规范
            System.out.println("flag true");
```

### 3.4 提示 G.FMT.12 减少不必要的空行，保持代码紧凑 (2)
<a id="level-3-4"></a>

**规则名称**: G.FMT.12 减少不必要的空行，保持代码紧凑
**问题数量**: 2

**问题描述**:
Reduce unnecessary blank lines to keep code compact.

**问题4.1**: java/test_java1.java:4,33

**问题代码**:
**问题代码1**: java/test_java1.java:4
```JAVA
import java.util.*;

public class HelloWorld {

    public static void main(String[] args) {
        System.out.println("Start");   // 1. 使用System.out（很多规则会告警）

        List list = new ArrayList();   // 2. 使用原始类型 raw type
        list.add("test");
```

**问题代码2**: java/test_java1.java:33
```JAVA
        if (flag == true) {           // 9. Boolean 比较写法不规范
            System.out.println("flag true");
        }

        long time = System.currentTimeMillis(); // 10. 未使用变量

    }
}
```

### 3.5 提示 G.CMT.05 文件头注释应该包含版权许可信息 (1)
<a id="level-3-4"></a>

**规则名称**: G.CMT.05 文件头注释应该包含版权许可信息
**问题数量**: 1

**问题描述**:
Missing file header comment at first line or file header comment not under the kia mark.

**问题5.1**: java/test_java1.java:1

**问题代码**:
**问题代码1**: java/test_java1.java:1
```JAVA
import java.util.*;

public class HelloWorld {

    public static void main(String[] args) {
        System.out.println("Start");   // 1. 使用System.out（很多规则会告警）
```

### 3.6 提示 G.NAM.08 布尔型变量建议以表达是非意义的动词开头 (1)
<a id="level-3-4"></a>

**规则名称**: G.NAM.08 布尔型变量建议以表达是非意义的动词开头
**问题数量**: 1

**问题描述**:
Boolean 'flag' should start with 'is', 'has', 'can' or 'should'

**问题6.1**: java/test_java1.java:27

**问题代码**:
**问题代码1**: java/test_java1.java:27
```JAVA
        try {
            int x = 10 / 0;           // 6. 明显异常
        } catch (Exception ex) {      // 7. 捕获过于宽泛
        }                             // 8. 空的 catch 块

        Boolean flag = true;
        if (flag == true) {           // 9. Boolean 比较写法不规范
            System.out.println("flag true");
        }

        long time = System.currentTimeMillis(); // 10. 未使用变量
```

### 3.7 提示 G.CMT.01 public或protected修饰的元素应添加Javadoc注释 (1)
<a id="level-3-4"></a>

**规则名称**: G.CMT.01 public或protected修饰的元素应添加Javadoc注释
**问题数量**: 1

**问题描述**:
Missing javadoc on 'HelloWorld' which is public or protected

**问题7.1**: java/test_java1.java:3

**问题代码**:
**问题代码1**: java/test_java1.java:3
```JAVA
import java.util.*;

public class HelloWorld {

    public static void main(String[] args) {
        System.out.println("Start");   // 1. 使用System.out（很多规则会告警）

        List list = new ArrayList();   // 2. 使用原始类型 raw type
```

### 3.8 提示 G.CMT.02 顶层public类的Javadoc应该包含功能说明和创建日期/版本信息 (1)
<a id="level-3-4"></a>

**规则名称**: G.CMT.02 顶层public类的Javadoc应该包含功能说明和创建日期/版本信息
**问题数量**: 1

**问题描述**:
Missing javadoc description

**问题8.1**: java/test_java1.java:2

**问题代码**:
**问题代码1**: java/test_java1.java:2
```JAVA
import java.util.*;

public class HelloWorld {

    public static void main(String[] args) {
        System.out.println("Start");   // 1. 使用System.out（很多规则会告警）

```

### 3.9 提示 G.FMT.02 一个源文件按顺序包含版权、package、import、顶层类，且用空行分隔 (1)
<a id="level-3-4"></a>

**规则名称**: G.FMT.02 一个源文件按顺序包含版权、package、import、顶层类，且用空行分隔
**问题数量**: 1

**问题描述**:
Do not use '*' in import declaration

**问题9.1**: java/test_java1.java:1

**问题代码**:
**问题代码1**: java/test_java1.java:1
```JAVA
import java.util.*;

public class HelloWorld {

    public static void main(String[] args) {
        System.out.println("Start");   // 1. 使用System.out（很多规则会告警）
```

### 3.10 提示 G.FMT.05 在条件语句和循环块中应该使用大括号 (1)
<a id="level-3-4"></a>

**规则名称**: G.FMT.05 在条件语句和循环块中应该使用大括号
**问题数量**: 1

**问题描述**:
Conditional statements and loop blocks must use braces.

**问题10.1**: java/test_java1.java:18

**问题代码**:
**问题代码1**: java/test_java1.java:18
```JAVA
        int c = 3;
        int d = 4;
        int e = 5;                     // 3. 多个未使用变量

        if (a == 1)
            System.out.println("no brace");  // 4. if 没有使用大括号

        String password = "123456";   // 5. 硬编码敏感信息

        try {
            int x = 10 / 0;           // 6. 明显异常
```
````
