// --- SERVER.JS (Backend) ---
// Технологии: Express, MongoDB, JWT, Speakeasy (для 2FA)

require('dotenv').config();
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy'); // Библиотека для генерации кодов 2FA
const QRCode = require('qrcode'); // Генерация QR картинки
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const UAParser = require('ua-parser-js'); // Парсинг User-Agent для определения устройства
const sharp = require('sharp'); // Библиотека для сжатия изображений

const REQUIRED_ENV_VARS = ['MONGO_URI', 'JWT_SECRET'];
REQUIRED_ENV_VARS.forEach((key) => {
    if (!process.env[key]) {
        console.error(`Missing required env variable: ${key}`);
        process.exit(1);
    }
});

const app = express();
// Настройка для корректного определения IP за прокси
app.set('trust proxy', true);
app.use(express.json({ limit: '50mb' })); // limit увеличен для загрузки картинок (base64)
app.use(cors());

// 1. Подключение к базе данных (MongoDB Atlas)
mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
    maxPoolSize: 10
})
    .then(() => console.log('MongoDB Connected'))
    .catch(err => {
        console.error('DB Error:', err);
        process.exit(1);
    });

// --- СХЕМЫ ДАННЫХ (MODELS) ---

const THEME_OPTIONS = ['amoled', 'dark', 'light'];
const ACCENT_OPTIONS = ['violet', 'blue', 'emerald', 'rose', 'orange'];

const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true }, // В реальном проекте используй bcrypt!
    twoFASecret: { type: Object }, // Здесь хранится секрет для Google Auth
    isTwoFAEnabled: { type: Boolean, default: false },
    preferences: {
        theme: { type: String, enum: THEME_OPTIONS, default: 'amoled' },
        accent: { type: String, enum: ACCENT_OPTIONS, default: 'violet' }
    }
});

const ProjectSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    title: { type: String, required: true, trim: true },
    items: [{
        _id: false,
        id: { type: String, required: true },
        type: { type: String, enum: ['text', 'image'], required: true },
        content: { type: String, required: true }, // Текст или Base64 картинки
        done: { type: Boolean, default: false }
    }]
}, { timestamps: true });

const TaskSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    text: { type: String, required: true, trim: true },
    done: { type: Boolean, default: false },
    deadline: { type: Date }
}, { timestamps: true });

const NoteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    title: { type: String, default: '', trim: true },
    content: { type: String, default: '' }
}, { timestamps: true });

const SessionSchema = new mongoose.Schema({
    sessionId: { type: String, unique: true, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    userAgent: { type: String, default: 'Неизвестное устройство' },
    ip: { type: String, default: '' },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now }
});
SessionSchema.index({ userId: 1, sessionId: 1 });

const User = mongoose.model('User', UserSchema);
const Project = mongoose.model('Project', ProjectSchema);
const Task = mongoose.model('Task', TaskSchema);
const Note = mongoose.model('Note', NoteSchema);
const Session = mongoose.model('Session', SessionSchema);

const createToken = (userId, sessionId) => jwt.sign({ id: userId, sessionId }, process.env.JWT_SECRET, { expiresIn: '12h' });

// Функция для сжатия Base64 изображений
const compressBase64Image = async (base64String, maxWidth = 1920, maxHeight = 1920, quality = 80) => {
    try {
        // Проверяем, что это действительно Base64 изображение
        if (!base64String || typeof base64String !== 'string' || !base64String.startsWith('data:image/')) {
            return base64String; // Возвращаем как есть, если это не изображение
        }

        // Извлекаем MIME тип и данные
        const matches = base64String.match(/^data:image\/([a-zA-Z]*);base64,(.*)$/);
        if (!matches || matches.length !== 3) {
            return base64String;
        }

        const mimeType = matches[1];
        const imageBuffer = Buffer.from(matches[2], 'base64');

        // Определяем формат вывода (JPEG для лучшего сжатия, кроме PNG если нужна прозрачность)
        const outputFormat = mimeType === 'png' ? 'png' : 'jpeg';
        const outputOptions = outputFormat === 'jpeg' 
            ? { quality, mozjpeg: true } 
            : { quality, compressionLevel: 9 };

        // Сжимаем изображение
        const compressedBuffer = await sharp(imageBuffer)
            .resize(maxWidth, maxHeight, {
                fit: 'inside',
                withoutEnlargement: true
            })
            .toFormat(outputFormat, outputOptions)
            .toBuffer();

        // Конвертируем обратно в Base64
        const compressedBase64 = compressedBuffer.toString('base64');
        return `data:image/${outputFormat};base64,${compressedBase64}`;
    } catch (error) {
        console.error('Ошибка при сжатии изображения:', error);
        // В случае ошибки возвращаем оригинал
        return base64String;
    }
};

// Функция для парсинга User-Agent и форматирования информации об устройстве
const parseDeviceInfo = (userAgentString) => {
    if (!userAgentString || userAgentString === 'Неизвестное устройство') {
        return 'Неизвестное устройство';
    }

    const parser = new UAParser(userAgentString);
    const result = parser.getResult();

    const os = result.os;
    const browser = result.browser;
    const device = result.device;

    const parts = [];

    // Определение ОС
    if (os.name) {
        let osName = os.name;
        if (osName === 'Windows') {
            // Определяем версию Windows более точно
            if (os.version) {
                const winVersion = parseFloat(os.version);
                if (winVersion >= 11.0) {
                    osName = 'Windows 11';
                } else if (winVersion >= 10.0) {
                    // Windows 10 (Windows 11 также может показывать 10.0 в user-agent)
                    // Более точное определение Windows 11 требует дополнительных проверок
                    osName = 'Windows 10';
                } else {
                    osName = `Windows ${os.version}`;
                }
            } else {
                osName = 'Windows';
            }
        } else if (osName === 'Android') {
            osName = os.version ? `Android ${os.version}` : 'Android';
        } else if (osName === 'iOS') {
            osName = os.version ? `iOS ${os.version}` : 'iOS';
        } else if (os.version) {
            osName = `${osName} ${os.version}`;
        }
        parts.push(osName);
    }

    // Определение устройства
    if (device.type) {
        if (device.type === 'mobile') {
            if (device.vendor) {
                parts.push(device.vendor);
            } else if (os.name === 'iOS') {
                parts.push('iPhone');
            } else if (os.name === 'Android') {
                parts.push('Android');
            }
        } else if (device.type === 'tablet') {
            if (os.name === 'iOS') {
                parts.push('iPad');
            } else {
                parts.push('Планшет');
            }
        }
    } else if (os.name === 'iOS' && !device.type) {
        // Если iOS, но тип устройства не определен, скорее всего iPhone
        parts.push('iPhone');
    }

    // Определение браузера
    if (browser.name) {
        let browserName = browser.name;
        if (browser.version) {
            // Берем только мажорную версию
            const majorVersion = browser.version.split('.')[0];
            browserName = `${browserName} ${majorVersion}`;
        }
        parts.push(browserName);
    }

    return parts.length > 0 ? parts.join(' • ') : 'Неизвестное устройство';
};

// Функция для получения IP адреса
const getClientIP = (req) => {
    // Проверяем заголовки прокси
    const forwarded = req.headers['x-forwarded-for'];
    const realIP = req.headers['x-real-ip'];
    
    let ip = null;
    
    if (forwarded) {
        ip = Array.isArray(forwarded)
            ? forwarded[0]
            : typeof forwarded === 'string'
                ? forwarded.split(',')[0]?.trim()
                : null;
    }
    
    if (!ip && realIP) {
        ip = realIP;
    }
    
    if (!ip) {
        ip = req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress;
    }
    
    // Обработка IPv6 localhost (::1) - конвертируем в IPv4 localhost
    if (ip === '::1' || ip === '::ffff:127.0.0.1') {
        ip = '127.0.0.1';
    }
    
    // Убираем префикс ::ffff: для IPv4-mapped IPv6 адресов
    if (ip && ip.startsWith('::ffff:')) {
        ip = ip.substring(7);
    }
    
    return ip || 'Неизвестный IP';
};

const createSessionRecord = async (userId, req) => {
    const sessionId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
    const userAgentString = req.headers['user-agent'] || 'Неизвестное устройство';
    const deviceInfo = parseDeviceInfo(userAgentString);
    const ip = getClientIP(req);

    const session = await Session.create({
        sessionId,
        userId,
        userAgent: deviceInfo, // Сохраняем отформатированную информацию об устройстве
        ip: ip,
        isActive: true
    });

    return session;
};

// --- MIDDLEWARE ---
// Middleware для проверки токена
const auth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization || '';
        if (!authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Auth failed' });
        }
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (!decoded?.sessionId) {
            return res.status(401).json({ error: 'Auth failed' });
        }

        const session = await Session.findOne({
            sessionId: decoded.sessionId,
            userId: decoded.id,
            isActive: true
        });

        if (!session) {
            return res.status(401).json({ error: 'Сессия устарела. Войдите заново.' });
        }

        session.lastSeen = new Date();
        session.isActive = true;
        session.save().catch(() => {});

        req.user = { id: decoded.id, sessionId: decoded.sessionId };
        req.session = session;
        next();
    } catch (e) {
        res.status(401).json({ error: 'Auth failed' });
    }
};

// --- API ROUTES ---

// Login (Шаг 1: Проверка пароля)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Укажите логин и пароль' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'Неверные данные' });
        }

        let isPasswordValid = user.password === password;
        if (!isPasswordValid && user.password?.startsWith('$2')) {
            isPasswordValid = await bcrypt.compare(password, user.password);
        }

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Неверные данные' });
        }

        // Если у пользователя включен 2FA, мы не даем токен сразу
        if (user.isTwoFAEnabled) {
            return res.json({ require2FA: true, userId: user._id, username: user.username });
        }

        // Если 2FA нет, даем доступ сразу
        const session = await createSessionRecord(user._id, req);
        const token = createToken(user._id, session.sessionId);
        res.json({
            token,
            sessionId: session.sessionId,
            userId: user._id,
            username: user.username,
            isTwoFAEnabled: false,
            preferences: user.preferences
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// --- ЛОГИКА 2FA (Google Authenticator) ---

// 1. Генерация секрета (Настройка 2FA)
// Пользователь вызывает это, когда нажимает "Включить 2FA"
app.post('/api/2fa/setup', async (req, res) => {
    try {
        const { userId } = req.body;
        const targetUserId = req.user?.id || userId;
        if (!targetUserId) {
            return res.status(400).json({ error: 'Не передан userId' });
        }

        if (req.user && req.user.id.toString() !== targetUserId.toString()) {
            return res.status(403).json({ error: 'Нет доступа к 2FA другого пользователя' });
        }

        const user = await User.findById(targetUserId);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        // Генерируем уникальный секрет для пользователя
        const secret = speakeasy.generateSecret({ name: "Tasco App (AlisherDEV)" });

        user.twoFASecret = {
            base32: secret.base32,
            otpauth_url: secret.otpauth_url
        };
        await user.save();

        // Генерируем QR код, который пользователь сканирует телефоном
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);
        res.json({ secret: secret.base32, qrCode, userId: user._id });
    } catch (error) {
        console.error('2FA setup error:', error);
        res.status(500).json({ error: 'Не удалось подготовить 2FA' });
    }
});

// 2. Верификация токена (Вход в систему)
app.post('/api/2fa/verify', async (req, res) => {
    try {
        const { userId, token } = req.body; // token - это 6 цифр с телефона
        if (!userId || !token) {
            return res.status(400).json({ success: false, error: 'Не переданы userId или token' });
        }

        const user = await User.findById(userId);
        if (!user?.twoFASecret?.base32) {
            return res.status(400).json({ success: false, error: '2FA не настроена' });
        }

        // Проверяем код с помощью speakeasy
        const verified = speakeasy.totp.verify({
            secret: user.twoFASecret.base32,
            encoding: 'base32',
            token: token, // Код, который ввел юзер
            window: 1
        });

        if (!verified) {
            return res.status(400).json({ success: false, error: 'Неверный код' });
        }

        // Если код верный - включаем 2FA (если была настройка) и даем JWT токен
        await User.findByIdAndUpdate(userId, { isTwoFAEnabled: true });
        const session = await createSessionRecord(user._id, req);
        const jwtToken = createToken(user._id, session.sessionId);
        res.json({
            success: true,
            token: jwtToken,
            sessionId: session.sessionId,
            userId: user._id,
            isTwoFAEnabled: true,
            preferences: user.preferences
        });
    } catch (error) {
        console.error('2FA verify error:', error);
        res.status(500).json({ success: false, error: 'Ошибка сервера' });
    }
});

app.post('/api/2fa/disable', auth, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { isTwoFAEnabled: false, twoFASecret: null });
        res.json({ success: true });
    } catch (error) {
        console.error('2FA disable error:', error);
        res.status(500).json({ success: false, error: 'Не удалось отключить 2FA' });
    }
});

// --- ОБЫЧНЫЕ ROUTE (Задачи, Проекты) ---

app.get('/api/projects', auth, async (req, res) => {
    try {
        const projects = await Project.find({ userId: req.user.id }).sort({ updatedAt: -1 });
        res.json(projects);
    } catch (error) {
        console.error('Fetch projects error:', error);
        res.status(500).json({ error: 'Не удалось получить проекты' });
    }
});

app.post('/api/projects', auth, async (req, res) => {
    try {
        const { title } = req.body;
        if (!title?.trim()) {
            return res.status(400).json({ error: 'Название проекта обязательно' });
        }
        const newProject = new Project({ title: title.trim(), items: [], userId: req.user.id });
        await newProject.save();
        res.status(201).json(newProject);
    } catch (error) {
        console.error('Create project error:', error);
        res.status(500).json({ error: 'Не удалось создать проект' });
    }
});

app.patch('/api/projects/:projectId/items', auth, async (req, res) => {
    try {
        const { projectId } = req.params;
        const { items } = req.body;
        if (!Array.isArray(items)) {
            return res.status(400).json({ error: 'Массив items обязателен' });
        }

        // Сжимаем все изображения в items перед сохранением
        const compressedItems = await Promise.all(items.map(async (item) => {
            if (item.type === 'image' && item.content) {
                const compressedContent = await compressBase64Image(item.content);
                return { ...item, content: compressedContent };
            }
            return item;
        }));

        const project = await Project.findOneAndUpdate(
            { _id: projectId, userId: req.user.id },
            { items: compressedItems },
            { new: true, runValidators: true }
        );

        if (!project) {
            return res.status(404).json({ error: 'Проект не найден' });
        }

        res.json(project);
    } catch (error) {
        console.error('Update project items error:', error);
        res.status(500).json({ error: 'Не удалось обновить проект' });
    }
});

// --- ACCOUNT & PREFERENCES ---
app.get('/api/account', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('username isTwoFAEnabled preferences');
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        res.json({
            userId: user._id,
            username: user.username,
            isTwoFAEnabled: user.isTwoFAEnabled,
            preferences: user.preferences
        });
    } catch (error) {
        console.error('Fetch account error:', error);
        res.status(500).json({ error: 'Не удалось получить профиль' });
    }
});

app.put('/api/account/preferences', auth, async (req, res) => {
    try {
        const updates = {};
        const { theme, accent } = req.body;
        if (theme) {
            if (!THEME_OPTIONS.includes(theme)) {
                return res.status(400).json({ error: 'Неверная тема' });
            }
            updates['preferences.theme'] = theme;
        }
        if (accent) {
            if (!ACCENT_OPTIONS.includes(accent)) {
                return res.status(400).json({ error: 'Неверный акцент' });
            }
            updates['preferences.accent'] = accent;
        }
        if (!Object.keys(updates).length) {
            return res.status(400).json({ error: 'Нет данных для обновления' });
        }

        const user = await User.findByIdAndUpdate(
            req.user.id,
            { $set: updates },
            { new: true, runValidators: true, select: 'preferences' }
        );

        res.json(user.preferences);
    } catch (error) {
        console.error('Update preferences error:', error);
        res.status(500).json({ error: 'Не удалось обновить настройки' });
    }
});

// --- SESSIONS ---
app.get('/api/sessions', auth, async (req, res) => {
    try {
        const sessions = await Session.find({ userId: req.user.id }).sort({ lastSeen: -1 });
        res.json({
            currentSessionId: req.user.sessionId,
            sessions: sessions.map((session) => ({
                sessionId: session.sessionId,
                userAgent: session.userAgent,
                ip: session.ip,
                createdAt: session.createdAt,
                lastSeen: session.lastSeen,
                isActive: session.isActive
            }))
        });
    } catch (error) {
        console.error('Fetch sessions error:', error);
        res.status(500).json({ error: 'Не удалось получить сессии' });
    }
});

app.delete('/api/sessions/:sessionId', auth, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const record = await Session.findOneAndDelete({ sessionId, userId: req.user.id });
        if (!record) {
            return res.status(404).json({ error: 'Сессия не найдена' });
        }
        const revokedCurrent = sessionId === req.user.sessionId;
        res.json({ revokedCurrent });
    } catch (error) {
        console.error('Delete session error:', error);
        res.status(500).json({ error: 'Не удалось завершить сессию' });
    }
});

app.get('/api/auth/check-session', auth, async (req, res) => {
    try {
        const session = await Session.findOne({
            sessionId: req.user.sessionId,
            userId: req.user.id
        });
        if (!session || !session.isActive) {
            return res.status(401).json({ error: 'Сессия неактивна' });
        }
        res.json({ isActive: true, sessionId: session.sessionId });
    } catch (error) {
        console.error('Check session error:', error);
        res.status(500).json({ error: 'Ошибка проверки сессии' });
    }
});

app.post('/api/auth/logout', auth, async (req, res) => {
    try {
        await Session.deleteOne({ sessionId: req.user.sessionId, userId: req.user.id });
        res.status(204).send();
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Не удалось выйти' });
    }
});

// --- TASKS ROUTES ---
app.get('/api/tasks', auth, async (req, res) => {
    try {
        const tasks = await Task.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json(tasks);
    } catch (error) {
        console.error('Fetch tasks error:', error);
        res.status(500).json({ error: 'Не удалось получить задачи' });
    }
});

app.post('/api/tasks', auth, async (req, res) => {
    try {
        const { text, deadline } = req.body;
        if (!text?.trim()) {
            return res.status(400).json({ error: 'Текст задачи обязателен' });
        }
        const task = await Task.create({
            text: text.trim(),
            deadline: deadline ? new Date(deadline) : undefined,
            userId: req.user.id
        });
        res.status(201).json(task);
    } catch (error) {
        console.error('Create task error:', error);
        res.status(500).json({ error: 'Не удалось создать задачу' });
    }
});

app.patch('/api/tasks/:taskId', auth, async (req, res) => {
    try {
        const { taskId } = req.params;
        const { text, done, deadline } = req.body;
        const updates = {};
        if (typeof text === 'string') {
            if (!text.trim()) {
                return res.status(400).json({ error: 'Текст задачи не может быть пустым' });
            }
            updates.text = text.trim();
        }
        if (typeof done === 'boolean') {
            updates.done = done;
        }
        if (deadline !== undefined) {
            updates.deadline = deadline ? new Date(deadline) : null;
        }

        if (!Object.keys(updates).length) {
            return res.status(400).json({ error: 'Нет данных для обновления' });
        }

        const task = await Task.findOneAndUpdate(
            { _id: taskId, userId: req.user.id },
            updates,
            { new: true, runValidators: true }
        );

        if (!task) {
            return res.status(404).json({ error: 'Задача не найдена' });
        }

        res.json(task);
    } catch (error) {
        console.error('Update task error:', error);
        res.status(500).json({ error: 'Не удалось обновить задачу' });
    }
});

app.delete('/api/tasks/:taskId', auth, async (req, res) => {
    try {
        const { taskId } = req.params;
        const deleted = await Task.findOneAndDelete({ _id: taskId, userId: req.user.id });
        if (!deleted) {
            return res.status(404).json({ error: 'Задача не найдена' });
        }
        res.status(204).send();
    } catch (error) {
        console.error('Delete task error:', error);
        res.status(500).json({ error: 'Не удалось удалить задачу' });
    }
});

// --- NOTES ROUTES ---
app.get('/api/notes', auth, async (req, res) => {
    try {
        const notes = await Note.find({ userId: req.user.id }).sort({ updatedAt: -1 });
        res.json(notes);
    } catch (error) {
        console.error('Fetch notes error:', error);
        res.status(500).json({ error: 'Не удалось получить заметки' });
    }
});

app.post('/api/notes', auth, async (req, res) => {
    try {
        const { title = '', content = '' } = req.body;
        if (!title.trim() && !content.trim()) {
            return res.status(400).json({ error: 'Заполните хотя бы одно поле' });
        }

        const note = await Note.create({
            title: title.trim(),
            content,
            userId: req.user.id
        });

        res.status(201).json(note);
    } catch (error) {
        console.error('Create note error:', error);
        res.status(500).json({ error: 'Не удалось создать заметку' });
    }
});

app.patch('/api/notes/:noteId', auth, async (req, res) => {
    try {
        const { noteId } = req.params;
        const { title, content } = req.body;
        const updates = {};

        if (typeof title === 'string') {
            updates.title = title.trim();
        }
        if (typeof content === 'string') {
            updates.content = content;
        }

        if (!Object.keys(updates).length) {
            return res.status(400).json({ error: 'Нет данных для обновления' });
        }

        const note = await Note.findOneAndUpdate(
            { _id: noteId, userId: req.user.id },
            updates,
            { new: true, runValidators: true }
        );

        if (!note) {
            return res.status(404).json({ error: 'Заметка не найдена' });
        }

        res.json(note);
    } catch (error) {
        console.error('Update note error:', error);
        res.status(500).json({ error: 'Не удалось обновить заметку' });
    }
});

app.delete('/api/notes/:noteId', auth, async (req, res) => {
    try {
        const { noteId } = req.params;
        const deleted = await Note.findOneAndDelete({ _id: noteId, userId: req.user.id });
        if (!deleted) {
            return res.status(404).json({ error: 'Заметка не найдена' });
        }
        res.status(204).send();
    } catch (error) {
        console.error('Delete note error:', error);
        res.status(500).json({ error: 'Не удалось удалить заметку' });
    }
});

// Статические файлы (логотип, изображения и т.д.)
// Разрешаем только определенные файлы для безопасности
app.get('/logo.png', (req, res) => {
    res.sendFile(path.join(__dirname, 'logo.png'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));