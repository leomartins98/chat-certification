const express = require('express');
const https = require('https');
const fs = require('fs');
const WebSocket = require('ws');
const crypto = require('crypto');
const path = require('path');

const app = express();

// Load SSL certificate
const options = {
    key: fs.readFileSync(path.join(__dirname, 'cert', 'key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'cert', 'cert.pem')),
};

// Create HTTPS server
const server = https.createServer(options, app);

// WebSocket setup
const wss = new WebSocket.Server({ server });

// 2. Gerenciamento de Clientes
// Usamos um Map para associar cada conexão (ws) aos dados do cliente (username, publicKey)
const clients = new Map();

// 3. Funções de Broadcast
// Modificada para aceitar um cliente a ser excluído (o próprio remetente)
function broadcast(message, excludeWs) {
    const data = JSON.stringify(message);
    clients.forEach((clientData, ws) => {
        // Envia para todos, exceto para o cliente a ser excluído
        if (ws !== excludeWs && ws.readyState === WebSocket.OPEN) {
            ws.send(data);
        }
    });
}

function broadcastUserList() {
    const userList = Array.from(clients.values()).map(c => c.username);
    broadcast({
        type: 'system',
        text: 'User list updated.',
        userList: userList
    });
}

// 4. Função de Verificação de Assinatura
function verifySignature(publicKey, signature, data) {
    try {
        const verify = crypto.createVerify('SHA256');
        verify.update(data);
        verify.end();

        // A chave pública é recebida no formato SPKI, codificada em base64.
        // O Node.js pode importá-la diretamente.
        const publicKeyObject = crypto.createPublicKey({
            key: Buffer.from(publicKey, 'base64'),
            format: 'der',
            type: 'spki'
        });

        return verify.verify(publicKeyObject, Buffer.from(signature, 'base64'));
    } catch (error) {
        console.error("Error during signature verification:", error);
        return false;
    }
}

// 5. Lógica de Conexão do WebSocket
wss.on('connection', ws => {
    console.log('Client connected');

    ws.on('message', message => {
        let data;
        try {
            data = JSON.parse(message);
        } catch (e) {
            console.log('Invalid JSON received, ignoring.');
            return;
        }

        const clientInfo = clients.get(ws);

        switch (data.type) {
            case 'join':
                if (!data.username || !data.publicKey) {
                    return ws.close(1008, "Username and public key are required.");
                }
                
                console.log(`${data.username} joined.`);
                clients.set(ws, {
                    username: data.username,
                    publicKey: data.publicKey
                });
                
                broadcastUserList();
                // Notifica os outros usuários que alguém entrou, excluindo o próprio usuário
                broadcast({ type: 'system', text: `${data.username} entrou no chat.` }, ws);
                break;

            case 'message':
                if (!clientInfo) {
                    return ws.close(1008, "Client must 'join' before sending messages.");
                }
                if (!data.text || !data.signature) {
                    return; // Ignora mensagens malformadas
                }

                // A etapa crucial: verificar a assinatura
                const isVerified = verifySignature(clientInfo.publicKey, data.signature, data.text);

                if (isVerified) {
                    // Assinatura válida: retransmite a mensagem para os outros
                    console.log(`Signature verified for message from ${clientInfo.username}`);
                    broadcast({
                        type: 'message',
                        username: clientInfo.username,
                        text: data.text
                    }, ws); // Passa o 'ws' para excluir o remetente
                } else {
                    // Assinatura inválida: informa o remetente e não retransmite
                    console.warn(`SIGNATURE VERIFICATION FAILED for user ${clientInfo.username}`);
                    ws.send(JSON.stringify({
                        type: 'system',
                        text: 'ERRO: Sua mensagem não foi enviada. A assinatura digital é inválida.'
                    }));
                }
                break;
        }
    });

    ws.on('close', () => {
        const clientInfo = clients.get(ws);
        if (clientInfo) {
            console.log(`${clientInfo.username} disconnected`);
            clients.delete(ws);
            broadcastUserList();
            broadcast({ type: 'system', text: `${clientInfo.username} saiu do chat.` });
        } else {
            console.log('A client disconnected without having joined.');
        }
    });
});

// 6. Iniciar o Servidor
const PORT = 443;
server.listen(PORT, () => {
    console.log(`Secure WebSocket server with signature verification started on port ${PORT}`);
});
