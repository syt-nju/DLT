const express = require("express");
const cors = require("cors");
const { Connection, Keypair, Transaction, SystemProgram, PublicKey, clusterApiUrl } = require("@solana/web3.js");

const app = express();
const PORT = 3000;

// 允许跨域请求
app.use(cors());
app.use(express.json());

app.post("/sendTransaction", async (req, res) => {
    try {
        console.log("收到请求:", req.body);

        // 这里直接写死私钥，并创建 Keypair
        const privateKeyBase58 = new Uint8Array([
            49, 198, 91, 67, 198, 82, 177, 153, 246, 226, 18, 28, 204, 90, 168, 237,
            25, 183, 195, 250, 87, 167, 35, 97, 218, 248, 179, 196, 81, 197, 57, 184,
            84, 196, 26, 124, 108, 139, 43, 223, 200, 119, 107, 154, 160, 7, 224, 84,
            58, 182, 224, 192, 105, 12, 195, 69, 110, 95, 156, 159, 209, 200, 101, 159
        ]);

        // 创建 keypair
        const keypair = Keypair.fromSecretKey(privateKeyBase58);

        // 获取请求中的参数
        const { recipient, amount } = req.body;

        // 参数验证
        if (!recipient || !amount) {
            return res.status(400).json({ error: "参数不完整" });
        }
        console.log("交易请求成功");
        // 连接到 Solana devnet
        let url =  'https://thrumming-lingering-telescope.solana-devnet.quiknode.pro/212022abf672b1c223b77531b80d7fd356e134b2/';
        connection = new Connection(url);
        console.log("连接solana成功")
        try {
            const blockhash = await connection.getRecentBlockhash();
            console.log("成功获取 Blockhash:", blockhash);
        } catch (error) {
            console.error("获取 Blockhash 失败:", error);
        }
        // 创建交易
        let transaction = new Transaction().add(
            SystemProgram.transfer({
                fromPubkey: keypair.publicKey,
                toPubkey: new PublicKey(recipient),
                lamports: amount,
            })
        );
        console.log("创建交易成功")
        // 发送交易
        let signature = await connection.sendTransaction(transaction, [keypair]);
        console.log("交易发送成功，哈希:", signature);

        // 返回交易哈希
        res.json({ success: true, signature });
    } catch (error) {
        console.error("交易失败:", error);
        res.status(500).json({ error: error.message });
    }
});

// 启动后端服务器
app.listen(PORT, () => {
    console.log(`🚀 后端运行在 http://localhost:${PORT}`);
});
