document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const loginModal = document.getElementById('login-modal');
    const chatAppContainer = document.getElementById('chat-app-container');
    const usernameInput = document.getElementById('username-input');
    const joinButton = document.getElementById('join-button');
    
    const userList = document.getElementById('user-list');
    const userCount = document.getElementById('user-count');
    const chatMessages = document.getElementById('chat-messages');
    const chatForm = document.getElementById('chat-input-form');
    const messageInput = document.getElementById('message-input');

    // --- State ---
    let ws;
    let username = '';
    let userKeyPair; // Armazenará o par de chaves (pública/privada) do usuário

    // --- Crypto Constants ---
    const keyGenParams = {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: 'SHA-256',
    };

    // --- Initialization ---
    usernameInput.focus();

    // --- Event Listeners ---
    joinButton.addEventListener('click', handleJoinChat);
    usernameInput.addEventListener('keyup', (event) => {
        if (event.key === 'Enter') handleJoinChat();
    });
    chatForm.addEventListener('submit', handleSendMessage);

    // --- Crypto Functions ---
    async function generateUserKeys() {
        try {
            userKeyPair = await window.crypto.subtle.generateKey(keyGenParams, true, ['sign', 'verify']);
            console.log('Par de chaves gerado para o usuário.');
        } catch (error) {
            console.error('Erro ao gerar chaves:', error);
            alert('Erro crítico: Não foi possível gerar as chaves de segurança. O chat não pode continuar.');
        }
    }

    async function getPublicKeyBase64() {
        if (!userKeyPair) return null;
        const publicKeyDer = await window.crypto.subtle.exportKey('spki', userKeyPair.publicKey);
        return btoa(String.fromCharCode.apply(null, new Uint8Array(publicKeyDer)));
    }

    async function signMessage(text) {
        if (!userKeyPair) return null;
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const signature = await window.crypto.subtle.sign(keyGenParams.name, userKeyPair.privateKey, data);
        return btoa(String.fromCharCode.apply(null, new Uint8Array(signature)));
    }

    // --- Main Functions ---
    async function handleJoinChat() {
        const name = usernameInput.value.trim();
        if (name) {
            username = name;
            
            // 1. Gerar chaves antes de qualquer outra coisa
            await generateUserKeys();
            if (!userKeyPair) return; // Para se a geração de chave falhar

            // 2. Mostrar o chat e conectar
            loginModal.classList.add('hidden');
            chatAppContainer.classList.remove('hidden');
            messageInput.focus();
            connectWebSocket();
        }
    }

    async function handleSendMessage(e) {
        e.preventDefault();
        const messageText = messageInput.value.trim();
        if (messageText && ws && ws.readyState === WebSocket.OPEN) {
            // 1. Assinar a mensagem com a chave privada
            const signature = await signMessage(messageText);
            if (!signature) {
                addSystemMessage('ERRO: Não foi possível assinar sua mensagem.');
                return;
            }

            // 2. Criar o payload com a assinatura
            const message = {
                type: 'message',
                text: messageText,
                signature: signature // A assinatura é enviada, não o nome de usuário direto
            };

            // 3. Enviar para o servidor
            ws.send(JSON.stringify(message));
            
            // 4. Adicionar à UI local (agora o username vem do estado local)
            addMessage({ username: username, text: messageText }, 'sent');
            messageInput.value = '';
        }
    }

    async function connectWebSocket() {
        // É crucial que as chaves já tenham sido geradas aqui
        const publicKeyBase64 = await getPublicKeyBase64();
        if (!publicKeyBase64) {
            addSystemMessage('ERRO: Chave pública não está disponível. Impossível conectar.');
            return;
        }

      
        ws = new WebSocket(`wss://${window.location.host}/ws`);

        ws.onopen = () => {
            console.log('Connected to WebSocket server.');
            // Envia o nome de usuário e a chave pública para se registrar no servidor
            ws.send(JSON.stringify({ 
                type: 'join', 
                username: username, 
                publicKey: publicKeyBase64 
            }));
        };

        ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                
                if (message.type === 'message') {
                    // A mensagem recebida já foi verificada pelo servidor
                    addMessage(message, 'received');
                } else if (message.type === 'system') {
                    addSystemMessage(message.text);
                    if (message.userList) {
                        updateUserList(message.userList);
                    }
                }
            } catch (error) {
                console.error('Error parsing message:', error);
            }
        };

        ws.onclose = () => {
            addSystemMessage('Você foi desconectado. A página será recarregada para gerar novas chaves de segurança.');
            setTimeout(() => window.location.reload(), 4000);
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            addSystemMessage('Erro de conexão. Verifique o console.');
        };
    }

    function updateUserList(users) {
        userList.innerHTML = ''; // Clear list
        users.forEach(user => {
            const userItem = document.createElement('div');
            userItem.className = 'user-item';
            
            const statusIcon = document.createElement('div');
            statusIcon.className = 'status-icon';
            
            const userName = document.createElement('span');
            userName.textContent = user;
            if (user === username) {
                userName.textContent += ' (Você)';
                userName.style.fontWeight = 'bold';
            }

            userItem.appendChild(statusIcon);
            userItem.appendChild(userName);
            userList.appendChild(userItem);
        });
        userCount.textContent = `(${users.length})`;
        updateTitle(users);
    }

    function updateTitle(users) {
        const otherUsers = users.filter(u => u !== username);
        let title = 'Chat Seguro com Assinatura Digital';
        if (otherUsers.length === 1) {
            title = `Chat com ${otherUsers[0]}`;
        } else if (otherUsers.length > 1) {
            const firstUser = otherUsers[0];
            const remainingCount = otherUsers.length - 1;
            title = `Chat com ${firstUser} e mais ${remainingCount}`;
        }
        document.title = title;
    }

    function addMessage(msg, type) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', type);

        // Adiciona o nome do usuário (remetente) para mensagens recebidas
        if (type === 'received') {
            const metaElement = document.createElement('div');
            metaElement.classList.add('meta');
            metaElement.textContent = msg.username; 
            messageElement.appendChild(metaElement);
        }

        const textElement = document.createElement('div');
        textElement.classList.add('text');
        textElement.textContent = msg.text;
        messageElement.appendChild(textElement);
        
        chatMessages.appendChild(messageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function addSystemMessage(text) {
        const systemMessageElement = document.createElement('div');
        systemMessageElement.classList.add('message', 'system');
        systemMessageElement.textContent = text;
        chatMessages.appendChild(systemMessageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
});
