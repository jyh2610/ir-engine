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

import { FilesViewModeSettings } from '@ir-engine/editor/src/services/FilesState'
import { getMutableState, useHookstate } from '@ir-engine/hyperflux'
import Button from '@ir-engine/ui/src/primitives/tailwind/Button'
import React, { ReactNode } from 'react'
import { HiDotsVertical } from 'react-icons/hi'
import { IoIosArrowDown, IoIosArrowForward } from 'react-icons/io'
import { twMerge } from 'tailwind-merge'
import { getParentCategories } from './helpers'
import { useAssetsCategory, useAssetsQuery } from './hooks'
import { AssetIconMap } from './icons'

function AssetCategory({ index }: { index: number }) {
  const { categories, currentCategoryPath, expandedCategories } = useAssetsCategory()
  const { refetchResources, staticResourcesPagination } = useAssetsQuery()
  const category = categories[index].value
  const selectedCategory = currentCategoryPath.at(-1)?.value
  const fontSize = useHookstate(getMutableState(FilesViewModeSettings).list.fontSize).value

  const handleClickCategory = () => {
    if (!category.isLeaf) expandedCategories[category.name].set(!category.collapsed)
    currentCategoryPath.set([...getParentCategories(categories.value, category.name), category])
    staticResourcesPagination.skip.set(0)
    refetchResources()
  }

  return (
    <div
      className={twMerge(
        'rounded-md bg-[#141619]',
        selectedCategory?.name === category.name && 'text-primary bg-[#191B1F]',
        category.depth === 0 ? 'min-h-9' : 'min-h-7'
      )}
      style={{
        height: `${fontSize}px`,
        fontSize: `${fontSize}px`
      }}
    >
      <div
        className={twMerge(
          'flex h-full w-full cursor-pointer items-center gap-2 overflow-hidden text-[#B2B5BD]',
          category.depth === 0 && !category.collapsed && 'mt-0'
        )}
        style={{
          marginLeft: category.depth > 0 ? category.depth * 16 : 0
        }}
        onClick={handleClickCategory}
      >
        <Button
          variant="transparent"
          className={twMerge('m-0 p-0', category.isLeaf && 'invisible cursor-auto')}
          title={category.collapsed ? 'expand' : 'collapse'}
          startIcon={category.collapsed ? <IoIosArrowForward /> : <IoIosArrowDown />}
          iconContainerClassName="ml-2"
        />
        <AssetIconMap name={category.name} />
        <div className="flex w-full items-center gap-1 text-nowrap pr-2">
          <span
            className={twMerge(
              "flex flex-row items-center gap-2 text-nowrap font-['Figtree'] text-[#e7e7e7]",
              selectedCategory?.name === category.name && 'text-[#F5F5F5]'
            )}
          >
            {category.name}
          </span>
        </div>
      </div>
    </div>
  )
}

export default function CategoriesList() {
  const { sidebarWidth, categories } = useAssetsCategory()

  return (
    <div
      className="mb-8 h-full space-y-1 overflow-x-hidden overflow-y-scroll bg-[#0E0F11] pb-8 pl-1 pr-2 pt-2"
      style={{ width: sidebarWidth.value }}
    >
      {categories.value.map((category, index) => (
        <AssetCategory key={category.name + index} index={index} />
      ))}
    </div>
  )
}

export function VerticalDivider({
  leftChildren,
  rightChildren
}: {
  leftChildren: ReactNode
  rightChildren: ReactNode
}) {
  const { sidebarWidth } = useAssetsCategory()
  const isDragging = useHookstate(false)
  return (
    <div
      className="flex h-full w-full overflow-hidden"
      onMouseUp={() => isDragging.set(false)}
      onMouseMove={(event) => {
        if (isDragging.value) sidebarWidth.set(event.pageX)
      }}
    >
      {leftChildren}
      <div className="flex w-5 cursor-pointer items-center">
        <HiDotsVertical
          onMouseDown={(event) => {
            event?.preventDefault()
            isDragging.set(true)
          }}
          className={twMerge('cursor-grab text-white', isDragging.value && 'cursor-grabbing')}
        />
      </div>
      {rightChildren}
    </div>
  )
}
