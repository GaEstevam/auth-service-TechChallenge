import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import amqp, { Channel } from 'amqplib';
import { collectDefaultMetrics, register, Gauge } from 'prom-client';

// Carregar variáveis de ambiente do .env
dotenv.config();

const app = express();
app.use(bodyParser.json());

// Carregar chave secreta para JWT
const JWT_SECRET = process.env.JWT_SECRET || 'secretkey';
const PORT = process.env.PORT || 3001;

// Interface do usuário (representação no banco de dados)
interface User {
  id: number;
  name: string;
  email: string;
  password: string; // senha criptografada
  role: string;
}

// Lista de usuários (como exemplo, normalmente seria um banco de dados)
const users: User[] = [];

// Conectar ao RabbitMQ (se necessário para emitir eventos)
let channel: Channel | null = null;
async function connectRabbitMQ(): Promise<void> {
  try {
    const connection = await amqp.connect('amqp://localhost');
    channel = await connection.createChannel();
    await channel.assertQueue('user_created');
    console.log('✅ Conectado ao RabbitMQ');
  } catch (error) {
    console.error('❌ Falha ao conectar ao RabbitMQ:', error);
  }
}
connectRabbitMQ();

// Rota de registro de usuário
app.post('/auth/register', async (req: Request, res: Response): Promise<void> => {
  try {
    const { name, email, password, role } = req.body;

    // Verificar se os dados estão presentes
    if (!name || !email || !password || !role) {
      res.status(400).json({ message: 'Todos os campos são obrigatórios' });
      return;
    }

    // Verificar se o usuário já existe
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      res.status(409).json({ message: 'Usuário já existe' });
      return;
    }

    // Criptografar a senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Criar novo usuário
    const user: User = {
      id: users.length + 1,
      name,
      email,
      password: hashedPassword,
      role,
    };

    users.push(user);

    // Enviar evento para RabbitMQ, se o canal estiver pronto
    if (channel) {
      channel.sendToQueue('user_created', Buffer.from(JSON.stringify(user)));
      console.log('📤 Evento user_created enviado');
    } else {
      console.warn('⚠️ Canal RabbitMQ não está pronto');
    }

    res.status(201).json({ message: 'Usuário registrado com sucesso' });
  } catch (error) {
    console.error('❌ Erro ao registrar usuário:', error);
    res.status(500).json({ message: 'Erro interno no servidor' });
  }
});

// Rota de login
app.post('/auth/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    // Verificar se o usuário existe
    const user = users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      res.status(401).json({ message: 'Credenciais inválidas' });
      return;
    }

    // Gerar o token JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (error) {
    console.error('❌ Erro ao fazer login:', error);
    res.status(500).json({ message: 'Erro interno no servidor' });
  }
});

// Rota de perfil de usuário (autenticado com JWT)
app.get('/auth/profile', (req: Request, res: Response): void => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    res.status(401).json({ message: 'Token ausente' });
    return;
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json(decoded);
  } catch {
    res.status(403).json({ message: 'Token inválido' });
  }
});

// Rota para métricas do Prometheus
app.get('/metrics', async (req: Request, res: Response) => {
  try {
    // Exemplo de métricas personalizadas
    const userCount = new Gauge({
      name: 'user_count',
      help: 'Número de usuários registrados no sistema',
    });
    userCount.set(users.length);

    // Coletando as métricas padrão
    collectDefaultMetrics();
    
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    res.status(500).send('Erro ao coletar métricas');
  }
});

// Inicialização do servidor
app.listen(PORT, () => {
  console.log(`🚀 Auth Service rodando na porta ${PORT}`);
});
