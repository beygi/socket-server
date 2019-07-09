import * as express from "express";
const align = require("string-align");
const chalk = require("chalk");
const socketioAuth = require("socketio-auth");
const jwt = require("jsonwebtoken");
const redis = require("redis");
const app = express();
const http = require("http").Server(app);
const io = require("socket.io")(http);

// public key to validate jwt
const pem = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAzv0loocOhwGhFaKXzkdHNwFYef+D3SFlJ1w8ZynT7NpA1Wg428Y1
pqU4kHNjuBYSt3YoeGOKkvMJHiWvYbgfEjZltodGcAJYFRIoQ3+1XSi/WWo53DK/
JtDEQUUsl9b0wrJdf7RX84ypBaU0AHUI94K0ts4P0ecPHwqqQuOZjHjBVPkLfHH6
DSJ9n0v1DVnSpcFZcwBBPrcPl3hT90M/mbCWnu8+j4VU38FAHz66nRJVtwgpvGmo
3sdia/Ue3bR9wEauKLOZ39mGUAP5RVncbUw6zslhCtrNuy0POSwx+u3Fi2UdH9hY
zClx8UlBd5j6T8nvprRw/ulCKzefMpXEQwIDAQAB
-----END RSA PUBLIC KEY-----`;

// server port
app.set("port", process.env.PORT || 2000);

// redis connection option
const retryStrategy = (options) => {
    if (options.error && options.error.code === "ECONNREFUSED") {
        return new Error("The server refused the connection");
    }
    return 1000;
};
const ConnectionOptions = {
    retry_strategy: retryStrategy,
};
if (process.env.REDIS_PASS) { ConnectionOptions[`password`] = process.env.REDIS_PASS; }

const pub = redis.createClient(process.env.REDIS_PORT || 6379, process.env.REDIS_HOST || "127.0.0.1", ConnectionOptions);
const sub = redis.createClient(process.env.REDIS_PORT || 6379, process.env.REDIS_HOST || "127.0.0.1", ConnectionOptions);

// subscribe to broadcast channel
sub.subscribe("broadcast");

app.get("/", (req: any, res: any) => {
    res.send("Socket service is up and running");
});

sub.on("message", (channel, message) => {
    // handle all messages
    console.log("Message from channel " + channel + ": " + message);

    // broad cast messages
    if (channel === "broadcast") {
        io.in("users").emit("message", message);
    }

    // user messages, pattern: "user: userid"
    if (channel.indexOf("user:") === 0) {
        io.in(channel).emit("user", message);
    }
});

// returns full list of connected clients
app.get("/listOfUsers", (req: any, res: any) => {
    io.of("/").adapter.clients(["users"], (err, clients) => {
        const list = clients.map((key) => {
            return { id: io.sockets.sockets[key].tokenParsed.sub, email: io.sockets.sockets[key].tokenParsed.email };
        });
        res.send(list);
    });
});

// event logger
const log = (status, client, error?: boolean) => {
    try {
        // remove from redis channels if exist
        const date = new Date();
        status = align(status, 15, "center");
        console.log((error ? chalk.bgRed.bold(`\n[${status}]`) : chalk.bgGreen.bold(`\n[${status}]`)) + "  " + chalk.bgBlue.bold(`[${date}]`));
        console.log(chalk.blueBright(`${client.tokenParsed.sub}:`) + "[" + chalk.green.bold(`${client.tokenParsed.email}`) + "]");
    } catch (error) {
        process.stderr.write(error.toString() + "\n");
    }
};

// authenticate user
const authenticate = (client, token, callback) => {
    try {
        // Verify and decode the token
        client.token = token;
        client.tokenParsed = jwt.decode(token);
        const decoded = jwt.verify(token, pem, {
            algorithms: ["RS256"],
        });
        callback(null, true);
    } catch (error) {
        // Token is not valid
        log("verifiy-failed", client, true);
        callback(error.toString());
        process.stderr.write(error.toString() + "\n");
    }
};

const verifyClient = (client) => {
    if (client.connected) {
        try {
            const decoded = jwt.verify(client.token, pem, {
                algorithms: ["RS256"],
            });
            log("still-valid", client);
            // validate again after 61 seconds
            setTimeout(() => { verifyClient(client); }, 61000);
        } catch (error) {
            // Token is expired
            log("expired", client, true);
            client.disconnect();
        }
    }
};

const postAuthenticate = (socket, data) => {
    // const username = data.username;
    log("verified", socket);

    // users channel for hold all connected users just in socket.io
    socket.join("users");

    // create a seperate channel for each user in redis and socket.io
    socket.join("user:" + socket.tokenParsed.sub);
    sub.subscribe("user:" + socket.tokenParsed.sub);

    // validate refreshed token from user
    socket.on("token", (token) => {
        log("new-token", socket);
        socket.token = token;
    });

    // verify jwt after 61 seconds
    setTimeout(() => { verifyClient(socket); }, 61000);
};

socketioAuth(io, {
    authenticate,
    postAuthenticate,
    // user must provide jwt right after connection. timeout is 2 seconds
    timeout: 2000,
});

io.on("connection", (socket) => {
    // must unsubscribe from redis channel when socket is disconnected
    socket.on("disconnect", () => {
        if (socket.tokenParsed && socket.tokenParsed.sub) {
            sub.unsubscribe("user:" + socket.tokenParsed.sub);
        }
        log("disconnected", socket, true);
    });
});

const server = http.listen(2000, () => {
    console.log("listening on *:2000");
});
