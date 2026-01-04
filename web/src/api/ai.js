import request from './request'

// AI生成POC
export function generatePoc(data) {
  return request.post('/ai/generatePoc', data)
}
