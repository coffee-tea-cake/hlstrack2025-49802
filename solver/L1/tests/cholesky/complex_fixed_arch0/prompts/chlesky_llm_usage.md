# 大模型辅助使用记录

## 基本信息

- **模型名称**：例如以下开源/可验证模型
  - GPT-5
- **提供方 / 访问方式**：
  - chatgpt.com
  - 阿里云 DashScope, 百度千帆, 智谱 AI 开放平台
  - 本地部署 (Ollama/vLLM/LM Studio)
- **使用日期**：2025-10-30
- **项目名称**：Cholesky  算子优化

---

## 使用场景 1

### 主要用途
代码重构
优化 cholesky.hppp 中导致高 latency 的函数（重点是 sqrt 实现）以降低单循环运行时间与整体 latency。
### 完整 Prompt 内容

cholesky.hppp完整代码粘贴个LLM（过长此处不展示）
假设你是一个FPGA工程师，现在需要优化一个矩阵运算算法，着重降低单循环运行时间和latency，
请你先大概理解这个代码，接下来我会通过report中一些细节和你一起降低latency

sys.rpt显示
x_sqrt_17_2_4_0_0_s 64 448.000 - 64 - no 0 0 700 2369 0，
go to source显示在87行ap_fixed<W1, I1, Q1, O1, N1> x_sqrt(ap_fixed<W1, I1, Q1, O1, N1> x) 
{ return hls::sqrt((double)x);}
latency达到66,这个怎么优化 }


### 模型输出摘要

return hls::sqrt((double)x);导致了latency达到66,解决方案如下
方案一：（定点版本）
return hls::sqrt(x);

方案二：为 sqrt 单独建 pipeline 函数
ap_fixed<W1, I1> sqrt_pipe(ap_fixed<W1, I1> in) {
    #pragma HLS pipeline II=1
    return hls::sqrt(in);
}
方案三：
template<int W, int I>
ap_fixed<W, I> fixed_sqrt(ap_fixed<W, I> x) {
#pragma HLS pipeline II=1
    ap_fixed<W, I> y = 1;
    for (int i = 0; i < 4; i++) {
#pragma HLS unroll
        y = (y + x / y) / 2;
    }
    return y;
}

### 人工审核与采纳情况
经验证，三种方案均在实施后无法达到预期效果，或有语法错误。
最终均未采纳。
---

## 使用场景 2
延续上一个使用场景
### 主要用途
<代码重构>
### 完整 Prompt 内容
Vitis报错如下：
[ERROR] /home/yanbo/Downloads/hlstrack2025-master/solver/L1/include/hw/utils/x_matrix_utils.hpp:89:8: error: no matching function for call to 'sqrt'
### 模型输出摘要

方案1：转为 float 后调用 HLS sqrt
#include "hls_math.h"

template <int W1, int I1, ap_q_mode Q1, ap_o_mode O1, int N1>
ap_fixed<W1, I1, Q1, O1, N1> x_sqrt(ap_fixed<W1, I1, Q1, O1, N1> x) {
#pragma HLS INLINE
    float xf = (float)x;           // 转成 float
    float yf = hls::sqrtf(xf);     // 用 HLS sqrtf
    return (ap_fixed<W1, I1, Q1, O1, N1>)yf;  // 再转回来
}
方案2：自定义定点 sqrt（Newton–Raphson 迭代）
template <int W, int I, ap_q_mode Q, ap_o_mode O, int N>
ap_fixed<W, I, Q, O, N> fixed_sqrt(ap_fixed<W, I, Q, O, N> x) {
#pragma HLS INLINE off
#pragma HLS PIPELINE II=1
    ap_fixed<W, I, Q, O, N> y = 1;
    for (int i = 0; i < 6; i++) {
#pragma HLS UNROLL
        y = (y + x / y) / 2;
    }
    return y;
}
### 人工审核与采纳情况
采用样本1,经testbench测试，将double转为float计算后，计算精度至少可保证至小数点后6位，没有丢失精度。
且Synthesis，Cosimulation和Implementation均成功
同时latency有显著降低，4919降低至2499
estimated time6.276涨至6.299，虽然略微上涨，但在7.00ns，uncertainty为10%的时钟下slack>0，总体性能显著提升
所以采用方案一
---

## 总结
在这次Cholesky算子优化项目中，我主要利用大模型的建议对代码进行了多轮修改与测试。虽然前几次尝试没有达到预期，但通过分析延迟来源，最终采用了将定点数转为浮点进行计算的方案，成功在保持一定精度的情况下显著降低了latency。这次过程让我更清楚地理解了FPGA优化中的取舍，也验证了模型辅助能在工程实践中提供实际帮助。
### 整体贡献度评估

大模型在本项目中的总体贡献占比：约 40%。
模型贡献：提供问题定位思路（识别到 double 转换为关键瓶颈），给出多条可行优化路线（使用 float、定点牛顿迭代、pipeline 分离等）。
人工贡献：完成对影响latency的函数的初始定位、进行兼容性调试、对AI给出的方案进行选择、与最终验证，人工介入与修正占 60%。
### 学习收获
这次优化让我对HLS工具的行为和定点运算的特性有了更深的理解，也锻炼了我分析性能瓶颈和调试硬件的能力。通过和大模型的交流，我学会了如何更系统地排查问题、验证假设并结合report数据做决策。虽然模型提供了思路，但最终的验证和实现需要我亲自完成，这让我对硬件开发流程更加熟悉，也提升了自己的独立思考能力。
---

## 附注

- 请确保填写真实、完整的使用记录
- 如未使用大模型辅助，请在此文件中注明"本项目未使用大模型辅助"
- 评审方将参考此记录了解项目的独立性与创新性
