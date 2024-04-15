/*
CPAL-1.0 License

The contents of this file are subject to the Common Public Attribution License
Version 1.0. (the "License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at
https://github.com/EtherealEngine/etherealengine/blob/dev/LICENSE.
The License is based on the Mozilla Public License Version 1.1, but Sections 14
and 15 have been added to cover use of software over a computer network and 
provide for limited attribution for the Original Developer. In addition, 
Exhibit A has been modified to be consistent with Exhibit B.

Software distributed under the License is distributed on an "AS IS" basis,
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
specific language governing rights and limitations under the License.

The Original Code is Ethereal Engine.

The Original Developer is the Initial Developer. The Initial Developer of the
Original Code is the Ethereal Engine team.

All portions of the code written by the Ethereal Engine team are Copyright © 2021-2023 
Ethereal Engine. All Rights Reserved.
*/

import React from 'react'

import HelpOutlineIcon from '@mui/icons-material/HelpOutline'
import InfoOutlined from '@mui/icons-material/InfoOutlined'
import { createStyles } from '@mui/material'
import Grid from '@mui/material/Grid'
import makeStyles from '@mui/styles/makeStyles'
import { twMerge } from 'tailwind-merge'
import { InfoTooltip } from '../../layout/Tooltip'

const useStyles = makeStyles<any, any, any>(() => {
  return createStyles({
    info: {
      color: 'var(--textColor)',
      height: '16px',
      width: 'auto',
      marginLeft: '5px'
    }
  })
})

/**
 * Used to provide styles for InputGroupContainer div.
 */
export const InputGroupContainer = ({ disabled = false, children, ...rest }) => (
  <div
    className={
      disabled ? 'pointer-events-none opacity-30' : 'flex min-h-[24px] flex-auto flex-row flex-nowrap px-2 py-1'
    }
    {...rest}
  >
    {children}
  </div>
)

/**
 * Used to provide styles for InputGroupContent div.
 */
export const InputGroupContent = ({ extraClassName = '', children }) => (
  <div
    className={twMerge(
      'ml-[5px] flex justify-between',
      '[&>label]:block [&>label]:w-[35%] [&>label]:pb-0.5 [&>label]:pt-1 [&>label]:text-[color:var(--textColor)]',
      '[&>*:first-child]:max-w-[calc(100%_-_2px)]',
      extraClassName
    )}
  >
    {children}
  </div>
)

export const InputGroupVerticalContainer = ({ disabled = false, children }) => (
  <div
    className={twMerge(
      disabled ? 'pointer-events-none opacity-30' : '',
      '[&>label]:block [&>label]:w-[35%] [&>label]:pb-0.5 [&>label]:pt-1 [&>label]:text-[color:var(--textColor)]'
    )}
  >
    {children}
  </div>
)

export const InputGroupVerticalContainerWide = ({ disabled = false, children }) => (
  <div
    className={twMerge(
      disabled ? 'pointer-events-none opacity-30' : '',
      '[&>label]:block [&>label]:w-full [&>label]:pb-0.5 [&>label]:pt-1 [&>label]:text-[color:var(--textColor)]'
    )}
  >
    {children}
  </div>
)

export const InputGroupVerticalContent = ({ children }) => <div className="flex flex-1 flex-col pl-2">{children}</div>
/**
 * Used to provide styles for InputGroupInfoIcon div.
 */
// change later
// .info  text-[color:var(--textColor)] h-4 w-auto ml-[5px]
export const InputGroupInfoIcon = ({ onClick = () => {} }) => (
  <HelpOutlineIcon
    className="ml-[5px] flex w-[18px] cursor-pointer self-center text-[color:var(--iconButtonColor)]"
    onClick={onClick}
  />
)

interface InputGroupInfoProp {
  info: string | JSX.Element
}

/**
 * Used to render InfoTooltip component.
 */
export function InputGroupInfo({ info }: InputGroupInfoProp) {
  return (
    <InfoTooltip title={info}>
      <InputGroupInfoIcon />
    </InfoTooltip>
  )
}

/**
 * Declaring proptypes for InputGroupInfo Component.
 */
export type InputGroupProps = React.PropsWithChildren<
  {
    name: string
    disabled?: boolean
    label?: string
    value?: any
    labelClasses?: string
    contentClasses?: string
  } & Partial<InputGroupInfoProp>
>

/**
 * InputGroup used to render the view of component.
 */
export function InputGroup({
  name,
  children,
  disabled,
  info,
  label,
  labelClasses,
  contentClasses,
  ...rest
}: InputGroupProps) {
  const styles = useStyles({})

  return (
    <InputGroupContainer disabled={disabled} {...rest}>
      <Grid container>
        <Grid item xs={4} display="flex" alignItems="center" justifyContent="end">
          <label className={`label ${labelClasses}`}>{label}</label>

          {info && (
            <InfoTooltip title={info}>
              <InfoOutlined className={styles.info} />
            </InfoTooltip>
          )}
        </Grid>
        <Grid item xs={8}>
          <InputGroupContent extraClassName={contentClasses}>{children}</InputGroupContent>
        </Grid>
      </Grid>
    </InputGroupContainer>
  )
}

export default InputGroup
