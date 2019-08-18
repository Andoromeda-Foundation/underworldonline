using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using Neo.SmartContract.Framework.Services.System;
using System;
using System.Numerics;
using System.ComponentModel;

namespace DGTContract
{
    public class DGT : SmartContract
    {
        [DisplayName("transfer")]
        public static event Action<byte[], byte[], BigInteger> Transferred;
        //合约拥有者
        private static readonly byte[] Owner = "AY5xLg4RPZPcYoD1fW7j455PkAybbU2x42".ToScriptHash();
        //精度
        private const ulong factor = 100000000;
        //总量
        private const ulong totalCoin = 100000000 * factor;
        /**
         * 合约入口
         */
        public static object Main(string method, object[] args)
        {
            if (Runtime.Trigger == TriggerType.Verification)
            {
                return Runtime.CheckWitness(Owner);
            }
            else if (Runtime.Trigger == TriggerType.Application)
            {
                byte[] callscript = ExecutionEngine.CallingScriptHash;

                if (method == "name") return Name();

                if (method == "symbol") return Symbol();

                if (method == "totalSupply") return TotalSupply();

                if (method == "decimals") return Decimals();

                if (method == "supportedStandards") return SupportedStandards();

                if (method == "balanceOf") return BalanceOf((byte[])args[0]);

                if (method == "transfer") return Transfer((byte[])args[0], (byte[])args[1], (BigInteger)args[2], callscript);

                if (method == "deployToken") return DeployToken();

                if (method == "airdropToken") return AirdropToken((byte[])args[0], (BigInteger)args[1]);

                if (method == "verifyAddress") return VerifyAddress((byte[])args[0], (string)args[1]);

                if (method == "getVerifyAddress") return GetVerifyAddress((byte[])args[0]);
            }
            return false;
        }
        //token的名称
        [DisplayName("name")]
        public static string Name() => "DGameToken";
        //token字符
        [DisplayName("symbol")]
        public static string Symbol() => "DGT";
        //token总发行量
        [DisplayName("totalSupply")]
        public static BigInteger TotalSupply()
        {
            return Storage.Get(Storage.CurrentContext, "totalSupply").AsBigInteger();
        }
        //token精度
        [DisplayName("decimals")]
        public static byte Decimals() => 8;
        //支持的标准
        [DisplayName("supportedStandards")]
        public static string[] SupportedStandards() => new string[] { "NEP-5", "NEP-7", "NEP-10" };
        //获取token余额
        [DisplayName("balanceOf")]
        public static BigInteger BalanceOf(byte[] account)
        {
            if (account.Length != 20)
                throw new InvalidOperationException("The parameter account SHOULD be 20-byte addresses.");
            var keyAddress = new byte[] { 0x11 }.Concat(account);
            return Storage.Get(Storage.CurrentContext, keyAddress).AsBigInteger();
        }
        //交易
        [DisplayName("transfer")]
        public static bool Transfer(byte[] from, byte[] to, BigInteger amount) => true;
        private static bool Transfer(byte[] from, byte[] to, BigInteger amount, byte[] callscript)
        {
            if (from.Length != 20 || to.Length != 20)
                throw new InvalidOperationException("The parameters from and to SHOULD be 20-byte addresses.");
            if (amount <= 0)
                throw new InvalidOperationException("The parameter amount MUST be greater than 0.");
            if (!IsPayable(to))
                return false;
            if (!Runtime.CheckWitness(from) && from.AsBigInteger() != callscript.AsBigInteger())
                return false;
            var keyFrom = new byte[] { 0x11 }.Concat(from);
            BigInteger fromAmount = Storage.Get(Storage.CurrentContext, keyFrom).AsBigInteger();
            if (fromAmount < amount)
                return false;
            if (from == to)
                return true;
            if (fromAmount == amount)
                Storage.Delete(Storage.CurrentContext, keyFrom);
            else
                Storage.Put(Storage.CurrentContext, keyFrom, fromAmount - amount);
            var keyTo = new byte[] { 0x11 }.Concat(to);
            BigInteger to_value = Storage.Get(Storage.CurrentContext, keyTo).AsBigInteger();
            Storage.Put(Storage.CurrentContext, keyTo, to_value + amount);
            Transferred(from, to, amount);
            return true;
        }
        /**
         * 是否可接受付款
         */
        private static bool IsPayable(byte[] to)
        {
            Contract c = Blockchain.GetContract(to);
            return c == null || c.IsPayable;
        }
        /**
         * 发布token
         */
        private static bool DeployToken()
        {
            if (!Runtime.CheckWitness(Owner))
                return false;
            byte[] total_supply = Storage.Get(Storage.CurrentContext, "totalSupply");
            if (total_supply.Length != 0)
                return false;
            var keySuperAdmin = new byte[] { 0x11 }.Concat(Owner);
            var owerCoin = totalCoin * 35 / 100;//官方
            Storage.Put(Storage.CurrentContext, keySuperAdmin, (ulong)owerCoin);
            var airdropCoin = totalCoin * 40 / 10;//空投
            Storage.Put(Storage.CurrentContext, "airdropToken", (ulong)airdropCoin);
            var builderCoin = totalCoin * 25 / 10;//生态建设
            Storage.Put(Storage.CurrentContext, "builderToken", (ulong)builderCoin);
            Storage.Put(Storage.CurrentContext, "totalSupply", totalCoin);
            Transferred(null, Owner, (ulong)owerCoin);
            return true;
        }
        /**
        * 空投token
        */
        private static bool AirdropToken(byte[] to, BigInteger amount)
        {
            if (!Runtime.CheckWitness(Owner))
                return false;
            BigInteger airdrop_token = Storage.Get(Storage.CurrentContext, "airdropToken").AsBigInteger();
            if (airdrop_token == null || airdrop_token <= 0) return false;
            Storage.Put(Storage.CurrentContext, "airdropToken", airdrop_token - amount);
            Transferred(null, to, amount);
            return true;
        }

        /**
         * 验证钱包地址和平台用户
         */
        private static bool VerifyAddress(byte[] address, string name)
        {
            if (!Runtime.CheckWitness(address))
                return false;
            var userKey = new byte[] { 0x13 }.Concat(address);
            byte[] username = Storage.Get(Storage.CurrentContext, userKey);
            if (username.Length != 0)
                return false;
            Storage.Put(Storage.CurrentContext, userKey, name);
            return true;
        }
        /**
         * 获取地址绑定平台用户
         */
        private static string GetVerifyAddress(byte[] address)
        {
            var userKey = new byte[] { 0x13 }.Concat(address);
            string name = Storage.Get(Storage.CurrentContext, userKey).AsString();
            return name;
        }

    }
}