using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using Neo.SmartContract.Framework.Services.System;
using System;
using System.Numerics;

namespace NeoContract3
{
    public class Contract1 : SmartContract
    {
        //合约管理员
        public static readonly byte[] ContractOwner = "ANR4GLPKZuZfLR4fm2tKTNR9hwBDftQoZP".ToScriptHash();
        //入口函数
        public static object Main(string operation, object[] args)
        {
            if (Runtime.Trigger == TriggerType.Verification)
            {//鉴权
                var tran = ExecutionEngine.ScriptContainer as Transaction;
                var outputs = tran.GetOutputs();
                for (var i = 0; i < outputs.Length; i++)
                {
                    var output = outputs[i];
                    if (output.ScriptHash != ContractOwner && output.ScriptHash != ExecutionEngine.ExecutingScriptHash)
                        return false;
                }
                return true;
            }
            else if (Runtime.Trigger == TriggerType.Application)
            {//应用
                if (operation == "writeName")
                {
                    byte[] name = (byte[])args[0];
                    Storage.Put(Storage.CurrentContext, "NEO", name);//存储
                    return true;
                }
                else if (operation == "getName")
                {
                    return Storage.Get(Storage.CurrentContext, "NEO");//提取
                }
            }
                return false;
        }
    }
}