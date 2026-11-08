import { supabase } from './supabase'

// Every query is scoped to the authenticated user's ID. Supabase RLS is the
// actual security boundary; this client-side filter is an additional guard.
export const investigationStore = {
  async list(userId) {
    const { data, error } = await supabase
      .from('investigations')
      .select('id, scan_id, filename, file_type, file_size_bytes, risk_score, risk_level, finding_count, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(100)
    if (error) throw error
    return (data || []).map((row) => ({ ...row, has_report: true }))
  },

  async save(userId, result, ocr) {
    const risk = result.risk_assessment || {}
    const row = {
      user_id: userId,
      scan_id: result.scan_id,
      filename: result.filename || 'unnamed-document',
      file_type: result.file_type || 'unknown',
      file_size_bytes: result.file_size_bytes || 0,
      risk_score: risk.risk_score ?? null,
      risk_level: risk.risk_level || 'unknown',
      finding_count: risk.finding_count ?? (risk.findings || []).length,
      report: result,
      ocr: ocr || null,
    }
    const { data, error } = await supabase
      .from('investigations')
      .upsert(row, { onConflict: 'user_id,scan_id' })
      .select('id, scan_id, filename, file_type, file_size_bytes, risk_score, risk_level, finding_count, created_at')
      .single()
    if (error) throw error
    return { ...data, has_report: true }
  },

  async get(userId, scanId) {
    const { data, error } = await supabase
      .from('investigations')
      .select('scan_id, filename, report, ocr')
      .eq('user_id', userId)
      .eq('scan_id', scanId)
      .single()
    if (error) throw error
    return data
  },

  async clear(userId) {
    const { error } = await supabase
      .from('investigations')
      .delete()
      .eq('user_id', userId)
    if (error) throw error
  },
}
