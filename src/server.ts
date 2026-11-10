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

const pool =new Pool({
    user:process.env.DB_USER,
    host: process.env.DB_HOST,
    database: 'projekt2_baza',
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
            res.json({success:true,
                message:`Prijavljeni stw kao "${u.username}"`
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

const port=Number(process.env.PORT)||3000;
app.listen(port,()=>{
    console.log(`Aplikacija radi na portu ${port}`);
});