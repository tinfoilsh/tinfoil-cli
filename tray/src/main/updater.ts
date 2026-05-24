import { app, dialog } from 'electron'
import pkg from 'electron-updater'

const { autoUpdater } = pkg

const UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000

let timer: NodeJS.Timeout | undefined

export function startAutoUpdater(): void {
  if (!app.isPackaged) return

  autoUpdater.autoDownload = true
  autoUpdater.autoInstallOnAppQuit = true

  autoUpdater.on('update-downloaded', async (info) => {
    const choice = await dialog.showMessageBox({
      type: 'info',
      title: 'Tinfoil update ready',
      message: `Tinfoil ${info.version} is ready to install.`,
      detail:
        'The update will be applied the next time you quit Tinfoil, or you can restart now.',
      buttons: ['Restart now', 'Later'],
      defaultId: 0,
      cancelId: 1,
      noLink: true
    })
    if (choice.response === 0) {
      autoUpdater.quitAndInstall()
    }
  })

  autoUpdater.on('error', (err) => {
    console.error('[updater]', err)
  })

  const run = () => {
    autoUpdater.checkForUpdates().catch(() => undefined)
  }

  run()
  timer = setInterval(run, UPDATE_CHECK_INTERVAL_MS)
}

export function stopAutoUpdater(): void {
  if (timer) {
    clearInterval(timer)
    timer = undefined
  }
}
