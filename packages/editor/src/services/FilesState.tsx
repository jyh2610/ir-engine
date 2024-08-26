/*
CPAL-1.0 License

The contents of this file are subject to the Common Public Attribution License
Version 1.0. (the "License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at
https://github.com/ir-engine/ir-engine/blob/dev/LICENSE.
The License is based on the Mozilla Public License Version 1.1, but Sections 14
and 15 have been added to cover use of software over a computer network and 
provide for limited attribution for the Original Developer. In addition, 
Exhibit A has been modified to be consistent with Exhibit B.

Software distributed under the License is distributed on an "AS IS" basis,
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
specific language governing rights and limitations under the License.

The Original Code is Infinite Reality Engine.

The Original Developer is the Initial Developer. The Initial Developer of the
Original Code is the Infinite Reality Engine team.

All portions of the code written by the Infinite Reality Engine team are Copyright © 2021-2023 
Infinite Reality Engine. All Rights Reserved.
*/

import { NotificationService } from '@ir-engine/client-core/src/common/services/NotificationService'
import { fileBrowserPath } from '@ir-engine/common/src/schema.type.module'
import { bytesToSize } from '@ir-engine/common/src/utils/btyesToSize'
import { FileDataType } from '@ir-engine/editor/src/components/assets/FileBrowser/FileDataType'
import { AssetLoader } from '@ir-engine/engine/src/assets/classes/AssetLoader'
import { defineState, NO_PROXY, syncStateWithLocalStorage, useMutableState } from '@ir-engine/hyperflux'
import { useFind, useMutation, useSearch } from '@ir-engine/spatial/src/common/functions/FeathersHooks'
import React, { createContext, ReactNode, useContext } from 'react'
import { handleUploadFiles } from '../functions/assetFunctions'

export const FilesViewModeState = defineState({
  name: 'FilesViewModeState',
  initial: {
    viewMode: 'icons' as 'icons' | 'list'
  },
  extension: syncStateWithLocalStorage(['viewMode'])
})

export const availableTableColumns = ['name', 'type', 'dateModified', 'size'] as const

export const FilesViewModeSettings = defineState({
  name: 'FilesViewModeSettings',
  initial: {
    icons: {
      iconSize: 90
    },
    list: {
      fontSize: 15,
      selectedTableColumns: {
        name: true,
        type: true,
        dateModified: true,
        size: true
      }
    }
  },
  extension: syncStateWithLocalStorage(['icons', 'list'])
})

export const FILES_PAGE_LIMIT = 100

export const FilesState = defineState({
  name: 'FilesState',
  initial: () => ({
    selectedDirectory: '',
    projectName: '',
    clipboardFile: null as { isCopy?: boolean; file: FileDataType } | null,
    searchText: ''
  })
})

const FilesQueryContext = createContext({
  filesQuery: null as null | ReturnType<typeof useFind<'file-browser'>>,
  files: [] as FileDataType[],
  onChangeDirectoryByPath: (_path: string) => {},
  onBackDirectory: () => {},
  onRefreshDirectory: async () => {},
  onCreateNewFolder: () => {}
})

export const CurrentFilesQueryProvider = ({ children }: { children?: ReactNode }) => {
  const filesState = useMutableState(FilesState)

  const filesQuery = useFind(fileBrowserPath, {
    query: {
      $limit: FILES_PAGE_LIMIT,
      directory: filesState.selectedDirectory.value
    }
  })

  const fileService = useMutation(fileBrowserPath)

  useSearch(
    filesQuery,
    {
      key: {
        $like: `%${filesState.searchText.value}%`
      }
    },
    filesState.searchText.value
  )

  const onChangeDirectoryByPath = (path: string) => {
    filesState.merge({ selectedDirectory: path })
    filesQuery.setPage(0)
  }

  const onBackDirectory = () => {
    const pattern = /([^/]+)/g
    const result = filesState.selectedDirectory.value.match(pattern)
    if (!result || result.length === 1) return
    let newPath = '/'
    for (let i = 0; i < result.length - 1; i++) {
      newPath += result[i] + '/'
    }
    onChangeDirectoryByPath(newPath)
  }

  const onRefreshDirectory = async () => {
    await filesQuery.refetch()
  }

  const onCreateNewFolder = () => fileService.create(`${filesState.selectedDirectory.value}New-Folder`)

  const files = filesQuery.data.map((file) => {
    const isFolder = file.type === 'folder'
    const fullName = isFolder ? file.name : file.name + '.' + file.type

    return {
      ...file,
      size: file.size ? bytesToSize(file.size) : '0',
      path: isFolder ? file.key.split(file.name)[0] : file.key.split(fullName)[0],
      fullName,
      isFolder
    }
  })

  return (
    <FilesQueryContext.Provider
      value={{ filesQuery, files, onChangeDirectoryByPath, onBackDirectory, onRefreshDirectory, onCreateNewFolder }}
    >
      {children}
    </FilesQueryContext.Provider>
  )
}

export const useCurrentFiles = () => useContext(FilesQueryContext)

export type DnDFileType = {
  dataTransfer: DataTransfer
  files: File[]
  items: DataTransferItemList
}

function isFileDataType(value: any): value is FileDataType {
  return value && value.key
}

export function useFileBrowserDrop() {
  const filesState = useMutableState(FilesState)
  const currentFiles = useCurrentFiles()
  const fileService = useMutation(fileBrowserPath)
  const isLoading = currentFiles.filesQuery?.status === 'pending'

  const moveContent = async (
    oldName: string,
    newName: string,
    oldPath: string,
    newPath: string,
    isCopy = false
  ): Promise<void> => {
    if (isLoading) return
    try {
      await fileService.update(null, {
        oldProject: filesState.projectName.value,
        newProject: filesState.projectName.value,
        oldName,
        newName,
        oldPath,
        newPath,
        isCopy
      })

      await currentFiles.onRefreshDirectory()
    } catch (error) {
      console.error('Error moving file:', error)
      NotificationService.dispatchNotify((error as Error).message, { variant: 'error' })
    }
  }

  const dropItemsOnFileBrowser = async (
    data: FileDataType | DnDFileType,
    dropOn?: FileDataType,
    selectedFileKeys?: string[]
  ) => {
    // if (isLoading) return
    const destinationPath = dropOn?.isFolder ? `${dropOn.key}/` : filesState.selectedDirectory.value

    if (selectedFileKeys && selectedFileKeys.length > 0) {
      await Promise.all(
        selectedFileKeys.map(async (fileKey) => {
          const file = currentFiles.files.find((f) => f.key === fileKey)
          if (file) {
            const newName = file.isFolder ? file.name : `${file.name}${file.type ? '.' + file.type : ''}`
            await moveContent(file.fullName, newName, file.path, destinationPath, false)
          }
        })
      )
    } else if (isFileDataType(data)) {
      if (dropOn?.isFolder) {
        const newName = data.isFolder ? data.name : `${data.name}${data.type ? '.' + data.type : ''}`
        await moveContent(data.fullName, newName, data.path, destinationPath, false)
      }
    } else {
      const path = filesState.selectedDirectory.get(NO_PROXY).slice(1)
      const filesToUpload = [] as File[]

      await Promise.all(
        data.files.map(async (file) => {
          const assetType = !file.type || file.type.length === 0 ? AssetLoader.getAssetType(file.name) : file.type
          if (!assetType || assetType === file.name) {
            await fileService.create(`${destinationPath}${file.name}`)
          } else {
            filesToUpload.push(file)
          }
        })
      )

      console.log('debug1 the files to upload', data)

      if (filesToUpload.length) {
        try {
          await handleUploadFiles(filesState.projectName.value, path, filesToUpload)
        } catch (err) {
          NotificationService.dispatchNotify(err.message, { variant: 'error' })
        }
      }
    }

    await currentFiles.onRefreshDirectory()
  }

  return dropItemsOnFileBrowser
}

export const canDropOnFileBrowser = (folderName: string) =>
  folderName.endsWith('/assets') ||
  folderName.indexOf('/assets/') !== -1 ||
  folderName.endsWith('/public') ||
  folderName.indexOf('/public/') !== -1

export const SelectedFilesState = defineState({
  name: 'FilesSelectedFilesState',
  initial: [] as FileDataType[]
})
