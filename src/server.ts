//web app koja omogućuje 2 različite tehnike sigurnosnih napada

//omogući i onemogući ranjivost - prekidač

//SQL Injection + Broken Authentication

import express, {Request, Response} from "express";
import {Pool, QueryResult} from "pg";
import path from "path";
import dotenv from 'dotenv';

dotenv.config()
const app=express();
app.use(express.json());
app.use(express.static(path.join(__dirname,"..","public")));

let sqlVulnerable=true;
let authVunerable=true;

const sessionStore= new Map<string, {id:number; username: string; role: string}>();

function randomToken(bytes=24):string{
    const chars="abcdef0123456789";
    let out="";
    for(let i=0;i<bytes*2;i++)out+=chars[Math.floor(Math.random()*chars.length)];
    return out;
}

type SessionUser={id:number;username:string;role:string};

function parseCookies(header:string|undefined):Record<string,string>{
    const out:Record<string,string>={}
    if(!header)return out;
    header.split(";").forEach((part)=>{
        const i=part.indexOf("=");
        if(i===-1)return;
        const k=part.slice(0,i).trim();
        const v=part.slice(i+1).trim();
        if(k)out[k]=decodeURIComponent(v);
    });
    return out;
}

function setSessionCookie(req:Request,res:Response,value:string){
    const secure=req.secure||req.headers["x-forwarded-proto"]==="https";
    res.setHeader(
        "Set-Cookie",
        `session=${value}; Path=/; SameSite=Lax${secure?"; Secure":""}`
    );
}

function clearSessionCookie(res:Response){
    res.setHeader("Set-Cookie","session=;Path=/;Max-Age=0");
}

function issueSession(req:Request,res:Response,user:SessionUser){
    if(authVunerable){
        const token=Buffer.from(JSON.stringify(user)).toString("base64");
        setSessionCookie(req,res,token);
    }else{
        const token=randomToken();
        sessionStore.set(token,user);
        setSessionCookie(req,res,token);
    }
}

function readSession(req:Request):SessionUser|null{
    const token=parseCookies(req.headers.cookie)["session"];
    if(!token)return null;
    if(authVunerable){
        try{
            const data=JSON.parse(Buffer.from(token,"base64").toString("utf8"));
            if(data && typeof data.id==="number" && typeof data.role==="string"){
                return data as SessionUser;
            }
            return null;
        }catch{
            return null;
        }
    }
    return sessionStore.get(token)??null;    
}
const pool =new Pool({
    user:process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password:process.env.DB_PASSWORD,
    port:5432,
    ssl:false
})

function errMsg(e:unknown):string{
    return e instanceof Error ? e.message :String(e);
}

app.get("/api/mode",(req:Request,res:Response)=>{
    res.json({sqlVulnerable,authVunerable});
});

app.post("/api/mode",(req:Request,res:Response)=>{
    if(Object.prototype.hasOwnProperty.call(req.body??{},"sqlVulnerable")){
        sqlVulnerable=Boolean(req.body.sqlVulnerable);
        console.log(`PREKIDAČ: SQL umetanje ranjivosti ${sqlVulnerable ? "UKLJUČENA":"ISKLJUČENA"}`);
    }
    if(Object.prototype.hasOwnProperty.call(req.body ?? {}, "authVulnerable")){
        authVunerable=Boolean(req.body.authVulnerable);
        console.log(`PREKIDAČ: broken authentification ${authVunerable ? "UKLJUČENA":"ISKLJUČENA"}`);
    }
    res.json({sqlVulnerable,authVunerable});
})

//zbog potreba aplikacije lozinke spremljene u čistom obliku 
app.post("/api/login",async (req,res)=>{
    const username=String(req.body?.username ?? "");
    const password=String(req.body?.password ?? "");

    try{
        let result:QueryResult;

        if(sqlVulnerable){
            const sql=`SELECT id, username, role FROM users WHERE username='${username}' AND password='${password}'`;
            result=await pool.query(sql);
        }else{
            const sql="SELECT id, username, role FROM users WHERE username = $1 AND password =$2";
            result=await pool.query(sql,[username,password]);        
        }
        if(result.rows.length>0){
            const u=result.rows[0];
            issueSession(req,res,{id:u.id,username:u.username,role:u.role});
            res.json({success:true,
                message:`Prijavljeni ste kao "${u.username}"`
            })
        }else{
            res.json({success:false, message:"Neispravno korisničko ime ili lozinka"});
        }
    }catch(e){
        res.json({
            success:false,
            message: sqlVulnerable ? `SQL greška: ${errMsg(e)}`: "Dogodila se greška."
        });
    }
});

app.get("/api/who",(req:Request,res:Response)=>{
    const user=readSession(req);
    res.json({authenticated:!!user,user});
});
app.post("/api/logout",(req:Request,res:Response)=>{
    clearSessionCookie(res);
    res.json({ok:true});
});
app.get("/api/admin",(req:Request,res:Response)=>{
    const user=readSession(req);
    if(!user || user.role!=="admin"){
        res.status(403).json({ok:false,message:"Zabranjen pristup - potrebna je uloga admin"});
        return;
    }
    res.json({ok:true,
        message:`Dobrodošli u admin ploču, ${user.username}!`,
        secret:"TAJNI PODATAK",
    });
});
const port=Number(process.env.PORT)||3000;
app.listen(port,()=>{
    console.log(`Aplikacija radi na portu ${port}`);
});