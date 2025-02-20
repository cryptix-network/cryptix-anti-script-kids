import asyncio
import os
from asyncio import Task, InvalidStateError
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi_utils.tasks import repeat_every
from collections import defaultdict
import time

import sockets
from server import app, cryptixd_client
from sockets import blocks
from sockets.blockdag import periodical_blockdag
from sockets.bluescore import periodical_blue_score
from sockets.coinsupply import periodic_coin_supply

print(
    f"Loaded: {sockets.join_room}"
    f"{periodic_coin_supply} {periodical_blockdag} {periodical_blue_score}")

BLOCKS_TASK = None 


MAX_PAYLOAD_SIZE = 2048 * 2048 


MAX_CONNECTIONS_PER_IP = 5


MAX_CONNECTIONS_IN_TIME_WINDOW = 60


TIME_WINDOW_SECONDS = 30


BLOCK_TIME_SECONDS = 3600


MAX_TOTAL_PAYLOAD = 200 * 1024 * 1024  


PAYLOAD_TIME_WINDOW = 60  


connection_history = defaultdict(list)


blocked_ips = defaultdict(int)


payload_history = defaultdict(int)  


class PayloadSizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host 
        

        current_time = time.time()
        if ip in blocked_ips and blocked_ips[ip] > current_time:
            return JSONResponse(
                content={"message": "Your IP is temporarily blocked due to excessive payload."},
                status_code=403
            )
        

        content_length = request.headers.get("Content-Length")
        if content_length:
            content_length = int(content_length)

            if content_length > MAX_PAYLOAD_SIZE:
                return JSONResponse(
                    content={"message": "Payload too large."},
                    status_code=413
                )
            

            payload_history[ip] += content_length

        response = await call_next(request)
        return response


class ConnectionLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host 
        

        current_time = time.time()
        if ip in blocked_ips and blocked_ips[ip] > current_time:
            return JSONResponse(
                content={"message": "Your IP is temporarily blocked."},
                status_code=403
            )
        

        connection_history[ip].append(current_time)


        connection_history[ip] = [timestamp for timestamp in connection_history[ip] if current_time - timestamp <= TIME_WINDOW_SECONDS]


        if len(connection_history[ip]) > MAX_CONNECTIONS_IN_TIME_WINDOW:
            blocked_ips[ip] = current_time + BLOCK_TIME_SECONDS
            return JSONResponse(
                content={"message": "Too many connections, you are blocked."},
                status_code=429
            )
        
        # Verarbeite die Anfrage
        response = await call_next(request)
        return response


@app.on_event("startup")
@repeat_every(seconds=PAYLOAD_TIME_WINDOW)
async def reset_payloads():
    current_time = time.time()


    for ip, total_payload in list(payload_history.items()):

        if current_time - payload_history[ip] > PAYLOAD_TIME_WINDOW:
            payload_history[ip] = 0
        

        if total_payload > MAX_TOTAL_PAYLOAD:
            blocked_ips[ip] = current_time + BLOCK_TIME_SECONDS


app.add_middleware(PayloadSizeMiddleware)
app.add_middleware(ConnectionLimitMiddleware)


@app.on_event("startup")
async def startup():
    global BLOCKS_TASK
 
    await cryptixd_client.initialize_all()
    BLOCKS_TASK = asyncio.create_task(blocks.config())


@app.on_event("startup")
@repeat_every(seconds=5)
async def watchdog():
    global BLOCKS_TASK

    try:
        exception = BLOCKS_TASK.exception()
    except InvalidStateError:
        pass
    else:
        print(f"Watch found an error! {exception}\n"
              f"Reinitialize cryptixds and start task again")
        await cryptixd_client.initialize_all()
        BLOCKS_TASK = asyncio.create_task(blocks.config())


@app.get("/", include_in_schema=False)
async def docs_redirect():
    return RedirectResponse(url='/docs')
    
    
# Tracking für die blockierten IPs
blocked_count = defaultdict(int)

@app.on_event("startup")
@repeat_every(seconds=10)  
async def show_top_ips_and_blocked():
    print("Task executed")  
    current_time = time.time()


    recent_connections = defaultdict(int)
    for ip, timestamps in connection_history.items():

        recent_connections[ip] = len([timestamp for timestamp in timestamps if current_time - timestamp <= 120])


    sorted_ips = sorted(recent_connections.items(), key=lambda x: x[1], reverse=True)[:10]
    print("Top 10 IPs with most connections in the last 2 minutes:")
    for ip, count in sorted_ips:
        print(f"IP: {ip}, Connections: {count}")


    blocked_ips_count = len(blocked_ips)
    print(f"Number of blocked IPs: {blocked_ips_count}")


    print("Block statistics:")
    for ip, block_time in blocked_ips.items():
        if block_time > current_time:
            blocked_count[ip] += 1


    sorted_blocked_ips = sorted(blocked_count.items(), key=lambda x: x[1], reverse=True)[:10]
    print("Top 10 blocked IPs due to excessive connections or payload:")
    for ip, block_count in sorted_blocked_ips:
        print(f"IP: {ip}, Blocked: {block_count} times")




if __name__ == '__main__':
    if os.getenv("DEBUG"):
        import uvicorn
        uvicorn.run(app)
