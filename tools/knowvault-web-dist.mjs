// Offline verification of the exact frontend shipped by Dockerfile.server.
// The builder image and dependency cache must already be provisioned locally.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

export const webBuilderImage = 'node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d'
const dependencyVolume = 'knowvault-web-build-node-modules'

function run(exe, args, options = {}) {
  const result = spawnSync(exe, args, { encoding: 'utf8', windowsHide: true, timeout: 180_000, maxBuffer: 16 * 1024 * 1024, ...options })
  if (result.error || result.status !== 0) throw new Error(`FRONTEND_CHECK_FAILED: ${exe}: ${result.error?.message || result.stderr || result.stdout || result.status}`)
  return result.stdout
}

const builder = String.raw`
import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
const root = '/tmp/web'
mkdirSync(root, { recursive: true })
for (const name of ['package.json', 'pnpm-lock.yaml', 'tsconfig.json']) copyFileSync('/input/'+name, root+'/'+name)
cpSync('/input/src', root+'/src', { recursive: true })
const require = createRequire(root+'/package.json')
const pkg = JSON.parse(readFileSync(root+'/package.json', 'utf8'))
if (process.versions.node !== pkg.engines.node) throw new Error('FRONTEND_NODE_VERSION_MISMATCH')
const normalized = path => readFileSync(path, 'utf8').replaceAll('\r\n', '\n')
// The frozen lock is the same one used by the CI builder, including transitives.
if (!existsSync(root+'/node_modules/.pnpm/lock.yaml') || normalized(root+'/pnpm-lock.yaml') !== normalized(root+'/node_modules/.pnpm/lock.yaml')) throw new Error('FRONTEND_DEPENDENCY_CACHE_LOCK_MISMATCH')
for (const [name, version] of Object.entries({...pkg.dependencies, ...pkg.devDependencies})) {
  const installed = require(name+'/package.json').version
  if (installed !== version) throw new Error('FRONTEND_DEPENDENCY_VERSION_MISMATCH: '+name)
}
function exec(args) {
  const result = spawnSync(process.execPath, args, { cwd: root, encoding: 'utf8', timeout: 120_000 })
  if (result.error || result.status !== 0) throw new Error('FRONTEND_BUILD_FAILED: '+(result.error?.message || result.stdout || result.stderr))
}
exec(['node_modules/typescript/bin/tsc', '--noEmit'])
exec(['node_modules/esbuild/bin/esbuild', 'src/main.tsx', '--bundle', '--format=esm', '--jsx=automatic', '--minify', '--outdir=dist/assets', '--target=es2025'])
copyFileSync(root+'/src/index.html', root+'/dist/index.html')
function files(path, prefix = '') {
  return readdirSync(path, {withFileTypes: true}).flatMap(entry => entry.isDirectory() ? files(join(path, entry.name), prefix+entry.name+'/') : [prefix+entry.name]).sort()
}
const built = files(root+'/dist')
const expected = files('/input/dist')
if (JSON.stringify(built) !== JSON.stringify(expected)) throw new Error('FRONTEND_DIST_FILESET_MISMATCH')
const hashes = {}
for (const name of built) {
  const actual = readFileSync(root+'/dist/'+name)
  if (!actual.equals(readFileSync('/input/dist/'+name))) throw new Error('FRONTEND_DIST_STALE: web/dist/'+name)
  hashes[name] = createHash('sha256').update(actual).digest('hex')
}
console.log(JSON.stringify({status: 'PASS', node: process.versions.node, esbuild: require('esbuild/package.json').version, files: hashes}))
`

export function verifyWebDist({ root = process.cwd(), revision } = {}) {
  root = resolve(root)
  let temporary
  let web = join(root, 'web')
  let exactRevision
  try {
    if (revision) {
      exactRevision = run('git', ['rev-parse', '--verify', `${revision}^{commit}`], { cwd: root }).trim()
      if (!/^[0-9a-f]{40}$/u.test(exactRevision)) throw new Error('FRONTEND_REVISION_INVALID')
      temporary = mkdtempSync(join(tmpdir(), 'knowvault-web-dist-'))
      const paths = run('git', ['ls-tree', '-r', '-z', '--name-only', exactRevision, '--', 'web'], { cwd: root }).split('\0').filter(Boolean)
      for (const path of paths) {
        if (!/^web\/(src\/|dist\/|package\.json$|pnpm-lock\.yaml$|tsconfig\.json$)/u.test(path)) continue
        const target = resolve(temporary, path)
        if (!target.startsWith(resolve(temporary) + sep)) throw new Error('FRONTEND_SNAPSHOT_PATH_INVALID')
        mkdirSync(dirname(target), { recursive: true })
        writeFileSync(target, run('git', ['show', `${exactRevision}:${path}`], { cwd: root, encoding: null }))
      }
      web = join(temporary, 'web')
    }
    // Inspect first: docker run must neither pull an image nor create an empty cache.
    run('docker', ['image', 'inspect', webBuilderImage])
    run('docker', ['volume', 'inspect', dependencyVolume])
    const output = run('docker', ['run', '--rm', '-i', '--pull=never', '--network=none',
      '--mount', `type=bind,source=${web},target=/input,readonly`,
      '--mount', `type=volume,source=${dependencyVolume},target=/tmp/web/node_modules,readonly`,
      webBuilderImage, 'node', '--input-type=module', '-'], { input: builder })
    return { ...JSON.parse(output.trim()), revision: exactRevision || 'WORKTREE', builderImage: webBuilderImage }
  } finally {
    if (temporary) {
      const target = resolve(temporary)
      if (dirname(target) !== resolve(tmpdir()) || !basename(target).startsWith('knowvault-web-dist-')) throw new Error('FRONTEND_CLEANUP_PATH_INVALID')
      rmSync(target, { recursive: true, force: true })
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2)
  if (args.length > 1 || args.some(arg => arg !== '--worktree' && !/^--revision=.+$/u.test(arg))) throw new Error('Usage: node tools/knowvault-web-dist.mjs --worktree|--revision=<commit>')
  const revision = args.find(arg => arg.startsWith('--revision='))?.slice('--revision='.length)
  console.log(JSON.stringify(verifyWebDist({ revision }), null, 2))
}
