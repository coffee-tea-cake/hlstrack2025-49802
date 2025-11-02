# 大模型辅助使用记录

## 基本信息

- **模型名称**：例如以下开源/可验证模型
  - GPT-5
- **提供方 / 访问方式**：
  - chatgpt.com
  - 阿里云 DashScope, 百度千帆, 智谱 AI 开放平台
  - 本地部署 (Ollama/vLLM/LM Studio)
- **使用日期**：2025-10-30
- **项目名称**：Lz4 算子优化


---

## 使用场景 1

### 主要用途
#pragma优化
优化 lz4_compress.hpp 中导致高 latency 的函数以降低单循环运行时间与整体 latency。
### 完整 Prompt 内容

lzCompress_6_4_65536_6_1_4096_64_Pipeline_dict_flush (1) 2050 3.075E4 - 2049 - loop auto-rewind stp (delay=0 clock cycles(s)) 0 0 15 41 0
这是synthesisrpt的显示，我个人猜测这是latency主要来源，怎么处理，
gotosource显示到
dict_flush: for (int i = 0; i < LZ_DICT_SIZE; i++) 
{ #pragma HLS PIPELINE II = 1 #pragma HLS UNROLL FACTOR = 2 dict[i] = resetValue; }
这一部分，可以考虑一下并行处理吗



### 模型输出摘要
在 HLS 中，可以使用 数组分区：
#pragma HLS ARRAY_PARTITION variable=dict cyclic factor=4 dim=1
配合 UNROLL FACTOR，一次可以写入 4 个或更多 entry，初始化 cycle 减少约 N 倍。


### 人工审核与采纳情况
经验证，将unroll参数由2调整为16后，虽然资源略微超限（guideline为70,shi实际为72.14%），但latency优化明显，采纳AI建议
---

## 总结

### 整体贡献度评估

大模型在本项目中的总体贡献占比：约 30%。
模型贡献：提供pragma优化思路，指出关键需要优化参数
人工贡献：完成对影响latency的函数的初始定位、进行不同参数的调试、对AI给出的方案进行调参、与最终验证，人工介入与修正占 70%。
### 学习收获
这次优化让我对HLS工具的行为获得更深技术理解，
理解 HLS pragma 行为机制，明确 PIPELINE、UNROLL、ARRAY_PARTITION 的实际作用范围与编译器限制。
掌握了存储结构与计算并行度之间的平衡关系，能根据资源约束选择合适的并行因子。
认识到BRAM 双端口瓶颈是延迟优化的关键因素，并学习了通过 bank 化与循环展开实现高效访问的方法。
证明了大模型在 算法结构分析与参数探索阶段 的价值，可显著节省工程调优时间。
---

## 附注

- 请确保填写真实、完整的使用记录
- 如未使用大模型辅助，请在此文件中注明"本项目未使用大模型辅助"
- 评审方将参考此记录了解项目的独立性与创新性
