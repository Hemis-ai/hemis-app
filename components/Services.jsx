'use client'

import { useEffect, useState } from 'react'
import { supabase } from '../../lib/supabase'

export default function Services() {
  const [services, setServices] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchServices = async () => {
      try {
        const { data, error } = await supabase
          .from('Services')
          .select('*')

        if (error) throw error
        setServices(data)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }

    fetchServices()
  }, [])

  if (loading) return <div>Loading...</div>
  if (error) return <div>Error: {error}</div>

  return (
    <div>
      <h1>Our Services</h1>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        {services.map((service) => (
          <div key={service.id} style={{ border: '1px solid #ccc', padding: '20px' }}>
            <h2>{service.Name}</h2>
            <p>{service.Description}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
