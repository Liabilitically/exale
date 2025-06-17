import React from 'react'

const Unauthorized = () => {
  return (
    <div className='flex justify-center items-center h-screen'>
        <div className='text-center'>
            <strong className='text-error text-3xl'>Access denied</strong><br/>
            <p className='text-2xl pt-1.5'>You are currently not authorized</p>
        </div>
    </div>
  )
}

export default Unauthorized