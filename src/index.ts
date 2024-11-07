import express from 'express'
import Logger from 'reggol'
import yaml from 'js-yaml'

const app = express()
const host = process.env.HOST ?? '127.0.0.1'
const port = process.env.PORT ? parseInt(process.env.PORT) : 30990
const logger = new Logger('app')
Logger.targets[0].showTime = 'yyyy-MM-dd hh:mm:ss'
{
  const lvl = parseInt(process.env.LOG_LEVEL ?? '2', 10)
  Logger.levels = { base: Number.isNaN(lvl) ? 2 : lvl }
}

const ua3fProxyName = '🤗 UA3F'

interface Proxy {
  name: string
  type: string
  server: string
  port: number
  url?: string
  udp?: boolean
  [k: string]: any
}

interface ProxyGroup {
  name: string
  type: string
  proxies: string[]
}

interface ClashConfig {
  proxies: Proxy[]
  'proxy-groups': ProxyGroup[]
  rules: string[]
  [k: string]: any
}

app.get('/api', async (req, res) => {
  if (!('url' in req.query) || typeof req.query.url !== 'string') {
    res.status(400).send({ error: 'url parameter is missing or not a string' })
    return
  }

  const subHeaders = new Headers()
  const reqUA = req.headers['user-agent']
  if (reqUA) {
    subHeaders.set('user-agent', reqUA)
  }
  const subRes = await fetch(req.query.url, {
    method: 'GET',
    headers: subHeaders,
    redirect: 'follow',
  })
  if (!subRes.ok) {
    const error =
      `failed to fetch ${req.query.url},` +
      ` code ${subRes.status}: ${await subRes.text()}`
    logger.error(error)
    res.status(subRes.status).send({ error })
    return
  }

  let sub: ClashConfig
  try {
    sub = yaml.load(await subRes.text(), { onWarning: logger.warn }) as any
  } catch (e) {
    logger.error(`failed to parse sub`)
    logger.error(e)
    res.status(500).send({ error: `failed to parse sub: ${e}` })
    return
  }

  if (req.query.server && typeof req.query.server !== 'string') {
    res.status(400).send({ error: 'has multiple server parameter' })
    return
  }
  if (req.query.port && typeof req.query.port !== 'string') {
    res.status(400).send({ error: 'has multiple port parameter' })
    return
  }

  const ua3fProxy = {
    name: ua3fProxyName,
    server: req.query.server ?? '127.0.0.1',
    port: req.query.port ? parseInt(req.query.port) : 1080,
    type: 'socks5',
    url: 'http://connectivitycheck.platform.hicloud.com/generate_204',
    udp: false,
  } satisfies Proxy

  try {
    sub.proxies.push(ua3fProxy)

    sub['proxy-groups'].forEach((group) => {
      if (group.proxies.includes('DIRECT') && !group.proxies.includes(ua3fProxyName)) {
        group.proxies.push(ua3fProxyName)
      }
    })

    sub.rules.unshift('PROCESS-NAME,ua3f,DIRECT')
    if (!sub.rules[sub.rules.length - 1].startsWith('MATCH,')) {
      sub.rules.push(`MATCH,${ua3fProxyName}`)
    }
  } catch (e) {
    logger.error(`failed to modify sub`)
    logger.error(e)
    res.status(500).send({ error: `failed to modify sub: ${e}` })
    return
  }

  res.setHeader('Content-Type', 'text/yaml')
  res.send(yaml.dump(sub))
})

app.use(express.static('public'))
app.route('/').all((req, res) => {
  res.sendFile('index.html', { root: 'public' })
})

app.listen(port, host, () => {
  logger.success(`listening on port ${port}`)
})
